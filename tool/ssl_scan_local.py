#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSL/Redirect Audit (Local CSV Version)
- domain-monitoring/data/<DATE>/ 아래의 CSV 파일들을 읽어
  인증서(CN/SAN/유효기간/일치여부) + HTTP 상태/리다이렉션 정보를 수집하여
  domain-monitoring/output/<DATE>/ssl_audit_result.csv 로 저장.

필수 파라미터
  --date YYYYMMDD           예: 20250814

선택 파라미터
  --data-root PATH          기본: ../data
  --output-root PATH        기본: ../output
  --files 파일목록          기본: lge.com.csv lge.co.kr.csv lgthinq.com.csv
  --url-columns 컬럼명들     기본: Url (대소문자 구분 없이 탐지)
  --limit N                 최대 처리 개수(테스트용). 0=전체
"""

import argparse
import csv
import datetime
import io
import os
import re
import socket
import ssl
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# ----- TLS 인증서 가져오기 (검증 실패 시에도 인증서만 최대한 획득) -----

def fetch_cert_pem(host: str, port: int = 443, timeout: float = 8.0) -> Tuple[Optional[str], Optional[str]]:
    """
    서버로 TLS 연결을 시도해 PEM 문자열과 오류문자열을 반환.
    1) 일반 검증 컨텍스트로 시도
    2) 실패하면 unverified 컨텍스트로 재시도하여 인증서만 획득
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                return ssl.DER_cert_to_PEM_cert(der), None
    except Exception as e1:
        try:
            ctx2 = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    return ssl.DER_cert_to_PEM_cert(der), f"(unverified) {e1}"
        except Exception as e2:
            return None, f"TLS connect error: {e1} / fallback: {e2}"

def parse_cert_with_pyopenssl(pem: str) -> Dict[str, Any]:
    """
    pyOpenSSL 로 인증서 주요 정보 추출 (CN/SAN/Validity/Issuer/Serial).
    """
    from OpenSSL import crypto  # pip install pyopenssl
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem.encode("utf-8"))

    # Subject CN
    subject = cert.get_subject()
    cn = getattr(subject, "CN", None)

    # Issuer CN
    issuer = cert.get_issuer()
    issuer_cn = getattr(issuer, "CN", None)

    # Validity
    def _to_dt(x: bytes) -> datetime.datetime:
        # ASN1_GENERALIZEDTIME 'YYYYMMDDHHMMSSZ'
        s = x.decode("ascii")
        return datetime.datetime.strptime(s, "%Y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc)

    not_before = _to_dt(cert.get_notBefore())
    not_after = _to_dt(cert.get_notAfter())
    days_to_expiry = (not_after - datetime.datetime.now(datetime.timezone.utc)).days

    # SAN
    san_list: List[str] = []
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name().decode().lower() == "subjectaltname":
            data = str(ext)  # "DNS:example.com, DNS:*.example.org"
            for part in data.split(","):
                part = part.strip()
                if part.startswith("DNS:"):
                    san_list.append(part[4:].strip())

    serial_hex = format(cert.get_serial_number(), "X")

    return {
        "cert_subject_cn": cn,
        "cert_san_list": san_list,
        "not_before_utc": not_before.isoformat(),
        "not_after_utc": not_after.isoformat(),
        "days_to_expiry": days_to_expiry,
        "issuer_cn": issuer_cn,
        "serial_hex": serial_hex,
    }

def hostname_match(host: str, san_list: List[str], cn: Optional[str]) -> Optional[bool]:
    """
    요청 호스트가 CN 또는 SAN 과 일치하는지 간단 판정.
    """
    patterns = list(san_list) if san_list else []
    if not patterns and cn:
        patterns.append(cn)

    if not patterns:
        return None  # 판단 불가

    def match(pat: str, h: str) -> bool:
        pat = pat.lower()
        h = h.lower()
        if pat.startswith("*."):
            # *.example.com -> sub.example.com (최소 한 단계 서브 필요)
            return h.endswith(pat[1:]) and h.count(".") > pat.count(".")
        return pat == h

    return any(match(p, host) for p in patterns)

# ----- HTTP/리다이렉션 확인 -----

def head_with_redirects(url: str, timeout: float = 10.0):
    """
    HEAD 요청을 origin(최초) → redirects → final(최종)까지 따라가며,
    - origin_status: 최초 응답 코드 (리다이렉트가 없으면 최종과 동일)
    - final_status : 최종 응답 코드
    - final_url    : 최종 URL
    - chain        : 중간 Location 목록
    - note         : verify=False 재시도 등 비고
    """
    import urllib3, requests
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    headers = {"User-Agent": "ssl-audit/1.0"}

    def summarize(resp: requests.Response):
        history = resp.history or []
        chain = [h.headers.get("Location", "") for h in history if h.is_redirect]
        origin_status = (history[0].status_code if history else resp.status_code)
        final_status  = resp.status_code
        final_url     = resp.url
        return origin_status, final_status, final_url, chain

    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout, headers=headers)
        origin_status, final_status, final_url, chain = summarize(r)
        return origin_status, final_status, final_url, chain, None
    except requests.exceptions.SSLError as e:
        try:
            r = requests.head(url, allow_redirects=True, timeout=timeout, headers=headers, verify=False)
            origin_status, final_status, final_url, chain = summarize(r)
            return origin_status, final_status, final_url, chain, f"insecure (verify=False) due to: {e}"
        except Exception as e2:
            return None, None, None, [], f"HTTP head error: {e} / fallback: {e2}"
    except Exception as e:
        return None, None, None, [], f"HTTP head error: {e}"


# ----- URL 파싱 -----

def normalize_url_for_request(u: str) -> Tuple[str, str, int]:
    """
    입력이 'example.com' 형태여도 https:// 를 붙여 사용.
    반환: (정규화URL, 호스트, 포트)
    """
    u = u.strip()
    if not u:
        return "", "", 443
    if not re.match(r"^https?://", u, flags=re.I):
        u = "https://" + u
    from urllib.parse import urlparse
    p = urlparse(u)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme.lower() == "https" else 80)
    return u, host, port

# ----- CSV 읽기 -----

def pick_url_from_row(row: Dict[str, str], url_columns: List[str]) -> Optional[str]:
    """
    지정한 후보 컬럼들 중에서 URL처럼 보이는 값을 선택.
    """
    # 대소문자 무시 매핑
    lower_map = {k.lower(): v for k, v in row.items()}
    for col in url_columns:
        if col.lower() in lower_map and lower_map[col.lower()]:
            return lower_map[col.lower()].strip()
    # fallback: 첫 번째로 URL 형태로 보이는 값
    for v in row.values():
        if isinstance(v, str) and (v.startswith("http://") or v.startswith("https://") or "." in v):
            return v.strip()
    return None

# ----- 메인 로직 -----

def main():
    ap = argparse.ArgumentParser(description="SSL/Redirect audit from local CSV files")
    ap.add_argument("--date", required=True, help="데이터 폴더(YYYYMMDD), 예: 20250814")
    ap.add_argument("--data-root", default=str(Path(__file__).resolve().parents[1] / "data"))
    ap.add_argument("--output-root", default=str(Path(__file__).resolve().parents[1] / "output"))
    ap.add_argument("--files", nargs="*", default=["lge.com.csv", "lge.co.kr.csv", "lgthinq.com.csv"])
    ap.add_argument("--url-columns", nargs="*", default=["Url"])
    ap.add_argument("--limit", type=int, default=0, help="최대 처리 건수 (0=전체)")
    args = ap.parse_args()

    date_folder = args.date
    data_dir = Path(args.data_root) / date_folder
    out_dir = Path(args.output_root) / date_folder
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ssl_audit_result.csv"

    input_files = [data_dir / fn for fn in args.files]
    missing = [str(p) for p in input_files if not p.exists()]
    if missing:
        print("[ERROR] 아래 입력 CSV가 존재하지 않습니다:\n  - " + "\n  - ".join(missing), file=sys.stderr)
        sys.exit(1)

    all_rows: List[Dict[str, Any]] = []
    for fpath in input_files:
        with open(fpath, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                all_rows.append(row)

    if args.limit > 0:
        all_rows = all_rows[: args.limit]

    results: List[Dict[str, Any]] = []
    for row in all_rows:
        url_raw = pick_url_from_row(row, args.url_columns)
        if not url_raw:
            continue

        norm_url, host, port = normalize_url_for_request(url_raw)
        if not host:
            continue

        # 기본 결과 스켈레톤
        item: Dict[str, Any] = {
            "input_url": url_raw,
            "normalized_url": norm_url,
            "host": host,
            "tls_handshake_ok": None,
            "cert_subject_cn": None,
            "cert_san_list": None,
            "hostname_match": None,
            "not_before_utc": None,
            "not_after_utc": None,
            "days_to_expiry": None,
            "issuer_cn": None,
            "serial_hex": None,
            "http_status_origin": None,
            "http_status_final": None,
            "http_status": None,
            "final_url": None,
            "redirect_chain": None,
            "http_note": None,
            "error": None,
        }

        # TLS 인증서
        cert_pem, tls_err = (None, None)
        if norm_url.lower().startswith("https://"):
            cert_pem, tls_err = fetch_cert_pem(host, port=port)
            if cert_pem:
                try:
                    info = parse_cert_with_pyopenssl(cert_pem)
                    item.update({
                        "tls_handshake_ok": True,
                        "cert_subject_cn": info.get("cert_subject_cn"),
                        "cert_san_list": ";".join(info.get("cert_san_list", [])) if info.get("cert_san_list") else None,
                        "not_before_utc": info.get("not_before_utc"),
                        "not_after_utc": info.get("not_after_utc"),
                        "days_to_expiry": info.get("days_to_expiry"),
                        "issuer_cn": info.get("issuer_cn"),
                        "serial_hex": info.get("serial_hex"),
                    })
                    item["hostname_match"] = hostname_match(
                        host,
                        info.get("cert_san_list", []),
                        info.get("cert_subject_cn"),
                    )
                except Exception as e:
                    item["tls_handshake_ok"] = True  # 인증서 가져오기는 성공
                    item["error"] = f"cert-parse error: {e}"
            else:
                item["tls_handshake_ok"] = False
                item["error"] = tls_err or "unknown TLS error"
        else:
            item["tls_handshake_ok"] = False  # http

        # HEAD 요청 (리다이렉션/상태)
        origin_code, final_code, final_url, chain, http_note = head_with_redirects(norm_url)
        item["http_status_origin"] = origin_code
        item["http_status_final"]  = final_code
        item["http_status"]        = final_code  # (하위호환: 기존 컬럼 유지, 최종 코드와 동일)
        item["final_url"] = final_url
        item["redirect_chain"] = " | ".join([c for c in chain if c]) if chain else None
        item["http_note"] = http_note


        results.append(item)

    # 저장
    fieldnames = [
        "input_url",
        "normalized_url",
        "host",
        "tls_handshake_ok",
        "cert_subject_cn",
        "cert_san_list",
        "hostname_match",
        "not_before_utc",
        "not_after_utc",
        "days_to_expiry",
        "issuer_cn",
        "serial_hex",
        "http_status_origin",
        "http_status_final",
        "http_status",
        "final_url",
        "redirect_chain",
        "http_note",
        "error",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in results:
            w.writerow(r)

    print(f"[OK] 결과 저장: {out_path} (총 {len(results)}건)")
    print("샘플:")
    if results:
        sample = results[0]
        for k in fieldnames:
            print(f"  {k}: {sample.get(k)}")

if __name__ == "__main__":
    # 의존성: pip install requests pyopenssl
    main()
