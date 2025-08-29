#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit_domain_ssl_certs.py
SSL/Redirect Audit for simplified CSVs (single 'Url' column)

입력:  data/<DATE>/{lge.com.csv, lge.co.kr.csv, lgthinq.com.csv} (header: Url)
출력:  output/<DATE>/<source>_ssl_audit_result.csv
       output/<DATE>/<source>_ssl_audit_result_reclassified.csv

의존성: pip install requests cryptography
사용 예:
  python audit_domain_ssl_certs.py --date 20250825 --limit 5 --tls-timeout 5 --http-timeout 6
"""

import argparse, csv, datetime as dt, re, socket, ssl, sys, traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import requests
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# -------------------- TLS 인증서 --------------------
def fetch_cert_pem(host: str, port: int = 443, timeout: float = 8.0) -> Tuple[Optional[str], Optional[str]]:
    """
    검증 컨텍스트로 시도 → 실패 시 검증 해제 컨텍스트로 재시도(인증서만 획득).
    실패 시 (None, 에러문구) 반환하고 상위에서 계속 진행.
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

# -------------------- 인증서 파싱 --------------------
def parse_cert_with_cryptography(pem: str) -> dict:
    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())

    def _cn(name) -> Optional[str]:
        try:
            return name.get_attributes_for_name(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            return None

    subject_cn = _cn(cert.subject)
    issuer_cn  = _cn(cert.issuer)

    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    not_after  = getattr(cert, "not_valid_after_utc",  None) or cert.not_valid_after
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=dt.timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=dt.timezone.utc)
    days_to_expiry = (not_after - dt.datetime.now(dt.timezone.utc)).days

    san_list: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = list(ext.value.get_values_for_type(x509.DNSName))  # 문자열 리스트
    except x509.ExtensionNotFound:
        pass

    serial_hex = format(cert.serial_number, "X")

    return {
        "cert_subject_cn": subject_cn,
        "cert_san_list": san_list,
        "not_before_utc": not_before.isoformat(),
        "not_after_utc":  not_after.isoformat(),
        "days_to_expiry": days_to_expiry,
        "issuer_cn": issuer_cn,
        "serial_hex": serial_hex,
    }

# -------------------- 유틸 --------------------
def normalize_url(u: str) -> Tuple[str, str, int, str]:
    u = (u or "").strip()
    if not u:
        return "", "", 443, "https"
    if not re.match(r"^https?://", u, flags=re.I):
        u = "https://" + u
    p = urlparse(u)
    host = p.hostname or ""
    scheme = (p.scheme or "https").lower()
    port = p.port or (443 if scheme == "https" else 80)
    return u, host, port, scheme

def hostname_match(host: str, san_list: List[str], cn: Optional[str]) -> Optional[bool]:
    pats = list(san_list) if san_list else []
    if not pats and cn:
        pats.append(cn)
    if not pats:
        return None
    def m(p: str, h: str) -> bool:
        p, h = p.lower(), h.lower()
        if p.startswith("*."):
            return h.endswith(p[1:]) and h.count(".") > p.count(".")
        return p == h
    return any(m(p, host) for p in pats)

def head_with_redirects(url: str, timeout: float = 10.0):
    """
    최초/최종 상태코드 모두 수집.
    반환: origin_status, final_status, final_url, chain(list), note
    """
    import urllib3
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
        return (*summarize(r), None)
    except requests.exceptions.SSLError as e:
        try:
            r = requests.head(url, allow_redirects=True, timeout=timeout, headers=headers, verify=False)
            origin_status, final_status, final_url, chain = summarize(r)
            return origin_status, final_status, final_url, chain, f"insecure (verify=false) due to: {e}"
        except Exception as e2:
            return None, None, None, [], f"HTTP head error: {e} / fallback: {e2}"
    except Exception as e:
        return None, None, None, [], f"HTTP head error: {e}"

def read_simple_url_csv(path: Path, url_col: str="Url") -> List[str]:
    urls: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            v = (row.get(url_col) or "").strip()
            if not v or v.startswith("#"):
                continue
            urls.append(v)
    seen, uniq = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq

# -------------------- 재분류 --------------------
def classify_risk_and_action(row: Dict[str, Any]) -> Tuple[str, str, str]:
    def _to_int(x):
        try:
            return int(x) if x not in (None, "") else None
        except Exception:
            return None

    days = _to_int(row.get("days_to_expiry"))
    final_url = (row.get("final_url") or "").lower()
    note = (row.get("http_note") or "")
    mismatch = row.get("hostname_match")
    if isinstance(mismatch, str):
        mismatch = mismatch.lower() == "true"

    expired   = (days is not None and days < 0)
    exp_soon  = (days is not None and 0 <= days <= 30)
    downgrade = final_url.startswith("http://")
    insecure  = ("insecure" in note.lower())

    if expired:
        risk, action = "Expired", "Renew certificate immediately"
    elif downgrade:
        risk, action = "Downgrade", "Force HTTPS and update redirects to https://"
    elif mismatch is False:
        risk, action = "Mismatch", "Reissue certificate or fix DNS/redirect"
    elif insecure:
        risk, action = "Insecure", "Fix certificate/chain so verification passes"
    elif exp_soon:
        risk, action = "ExpiringSoon", "Schedule renewal within 30 days"
    else:
        risk, action = "None", "No action"

    if expired or downgrade:
        sev = "Critical"
    elif (mismatch is False) or (days is not None and 0 <= days <= 7):
        sev = "High"
    elif insecure or (days is not None and 8 <= days <= 90):
        sev = "Medium"
    else:
        sev = "Low"

    return risk, sev, action

# -------------------- 메인 --------------------
def main():
    ap = argparse.ArgumentParser(description="SSL/Redirect audit for simplified CSVs (Url column only)")
    ap.add_argument("--date", required=True, help="예: 20250825")
    ap.add_argument("--data-root",   default=str(Path(__file__).resolve().parents[1] / "data"))
    ap.add_argument("--output-root", default=str(Path(__file__).resolve().parents[1] / "output"))
    ap.add_argument("--files", nargs="*", default=["lge.com.csv", "lge.co.kr.csv", "lgthinq.com.csv"])
    ap.add_argument("--url-column", default="Url")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--tls-timeout", type=float, default=5.0, help="TLS 소켓 연결 타임아웃(초)")
    ap.add_argument("--http-timeout", type=float, default=6.0, help="HTTP HEAD 타임아웃(초)")
    args = ap.parse_args()

    data_dir = Path(args.data_root) / args.date
    out_dir  = Path(args.output_root) / args.date
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_fields = [
        "input_url","normalized_url","host",
        "tls_handshake_ok","cert_subject_cn","cert_san_list","hostname_match",
        "not_before_utc","not_after_utc","days_to_expiry","issuer_cn","serial_hex",
        "http_status_origin","http_status_final","http_status",
        "final_url","redirect_chain","http_note","error",
    ]
    rcf_fields = raw_fields + ["risk_type","severity","recommended_action"]

    input_paths = [data_dir / fn for fn in args.files]
    missing = [str(p) for p in input_paths if not p.exists()]
    if missing:
        print("[ERROR] Missing input CSV:\n  - " + "\n  - ".join(missing), file=sys.stderr)
        sys.exit(1)

    def save_outputs(stem: str, results: List[Dict[str, Any]]):
        raw_path = out_dir / f"{stem}_ssl_audit_result.csv"
        rcf_path = out_dir / f"{stem}_ssl_audit_result_reclassified.csv"
        with open(raw_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=raw_fields); w.writeheader(); w.writerows(results)
        rcf_rows: List[Dict[str, Any]] = []
        for r in results:
            risk_type, severity, action = classify_risk_and_action(r)
            r2 = dict(r); r2.update({"risk_type": risk_type, "severity": severity, "recommended_action": action})
            rcf_rows.append(r2)
        with open(rcf_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=rcf_fields); w.writeheader(); w.writerows(rcf_rows)
        print(f"[OK] {stem}: {len(results)} rows → {raw_path}, {rcf_path}")

    for path in input_paths:
        urls = read_simple_url_csv(path, args.url_column)
        if args.limit > 0:
            urls = urls[:args.limit]

        results: List[Dict[str, Any]] = []
        stem = path.stem
        print(f"[FILE] Start: {stem} ({len(urls)} urls)")

        try:
            for url_raw in urls:
                print(f"[INFO] Checking {url_raw} ...")
                norm_url, host, port, scheme = normalize_url(url_raw)
                item: Dict[str, Any] = {k: None for k in raw_fields}
                item.update({"input_url": url_raw,"normalized_url": norm_url,"host": host})

                # TLS
                if scheme == "https" and host:
                    cert_pem, tls_err = fetch_cert_pem(host, port=port, timeout=args.tls_timeout)
                    if cert_pem:
                        try:
                            info = parse_cert_with_cryptography(cert_pem)
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
                            item["hostname_match"] = hostname_match(host, info.get("cert_san_list", []), info.get("cert_subject_cn"))
                        except Exception as e:
                            item["tls_handshake_ok"] = True
                            item["error"] = f"cert-parse error: {e}"
                    else:
                        item["tls_handshake_ok"] = False
                        item["error"] = tls_err or "unknown TLS error"
                else:
                    item["tls_handshake_ok"] = False

                # HEAD
                origin_code, final_code, final_url, chain, http_note = head_with_redirects(norm_url, timeout=args.http_timeout)
                item["http_status_origin"] = origin_code
                item["http_status_final"]  = final_code
                item["http_status"]        = final_code
                item["final_url"] = final_url
                item["redirect_chain"] = " | ".join([c for c in chain if c]) if chain else None
                item["http_note"] = http_note

                risk, sev, _ = classify_risk_and_action(item)
                print(f"[DONE] {url_raw} → status={final_code}, risk={risk}, severity={sev}")

                results.append(item)

            # 파일별 저장
            save_outputs(stem, results)

        except KeyboardInterrupt:
            # Ctrl+C 시, 지금까지의 결과를 저장하고 종료
            print("\n[INTERRUPTED] Ctrl+C detected. Saving partial results...")
            try:
                save_outputs(stem, results)
            except Exception as e:
                print(f"[WARN] Failed to save partial results for {stem}: {e}", file=sys.stderr)
            sys.exit(130)  # 128+SIGINT

        except Exception as e:
            # 예기치 못한 예외: 부분 저장 + 다음 파일로 진행
            print(f"[ERROR] Unexpected error on {stem}: {e}", file=sys.stderr)
            traceback.print_exc()
            try:
                save_outputs(stem, results)
            except Exception as e2:
                print(f"[WARN] Failed to save partial results for {stem}: {e2}", file=sys.stderr)

if __name__ == "__main__":
    main()
