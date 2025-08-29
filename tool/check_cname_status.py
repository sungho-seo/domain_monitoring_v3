#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
대량 CNAME 검사기 (비동기)
- 입력 CSV 형식: Label/Name,Type,R Data
- Type이 CNAME인 레코드만 검사
- Label/Name이 상대 이름이면 origin을 붙여 FQDN으로 변환
- 기대값(R Data)과 실제 질의 결과(CNAME)가 일치하는지 검사
- 결과를 콘솔 및 CSV로 저장

사용 예시:
  python3 check_cname_bulk.py \
    --csv data/lge.com.csv \
    --csv data/lge.co.kr.csv \
    --csv data/lgthinq.com.csv \
    --concurrency 300 \
    --timeout 3 \
    --retries 2

origin 추론 규칙:
- --origin-map "lge.com=data/lge.com.csv,lge.co.kr=data/lge.co.kr.csv,lgthinq.com=data/lgthinq.com.csv"
  (파일 경로에 매칭되면 해당 origin 사용)
- 또는 파일명에 'lge.com', 'lge.co.kr', 'lgthinq.com' 문자열이 들어있으면 자동 매핑
- 또는 CSV 안의 Label/Name이 이미 FQDN이면 그대로 사용
"""

import argparse
import asyncio
import csv
import datetime as dt
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

import pandas as pd
import dns.asyncresolver
import dns.exception
import dns.name

PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

def norm_name(s: str) -> str:
    """도메인 비교용 정규화 (마침표, 소문자)"""
    return s.strip().rstrip(".").lower()

def maybe_join_origin(label: str, origin: Optional[str]) -> str:
    """label이 FQDN 아니면 origin 붙여서 FQDN으로"""
    label = label.strip()
    if not label:
        return label
    # 이미 FQDN?
    if label.endswith("."):
        return label
    # 점이 많이 들어있어도 절대이름이 아닐 수 있어 Route53 export 등
    if origin and not re.search(r"\.[a-zA-Z]{2,}$", label):
        return f"{label}.{origin}."
    # 확실히 TLD가 보이면 FQDN으로 간주하고 마지막 점 추가
    if re.search(r"\.[a-zA-Z]{2,}$", label):
        return label + "."
    # 남는 경우에도 origin이 있으면 붙여준다
    if origin:
        return f"{label}.{origin}."
    return label + "."

def guess_origin_from_path(path: str) -> Optional[str]:
    low = path.lower()
    for d in ["lgthinq.com", "lge.co.kr", "lge.com"]:
        if d in low:
            return d
    return None

def parse_origin_map(s: str) -> Dict[str, str]:
    """
    "lge.com=pathA,lge.co.kr=pathB,lgthinq.com=pathC" 형태를 dict로
    값은 'path' substring 매칭용으로 사용 (파일 경로에 포함되면 origin 적용)
    """
    m: Dict[str, str] = {}
    for pair in s.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ValueError("--origin-map 형식 오류: " + pair)
        origin, pathfrag = pair.split("=", 1)
        m[origin.strip()] = pathfrag.strip()
    return m

class CNAMEChecker:
    def __init__(self, concurrency: int, timeout: float, retries: int, resolvers: List[str]):
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.retries = retries
        self.resolvers = resolvers
        self.cache: Dict[str, Tuple[bool, str]] = {}  # name -> (ok, actual)

    async def query_cname_once(self, fqdn: str, resolver_ip: str) -> Optional[str]:
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = [resolver_ip]
        r.lifetime = self.timeout
        try:
            ans = await r.resolve(fqdn, "CNAME", raise_on_no_answer=False)
            if ans.rrset:
                # 첫 번째 CNAME만 비교 대상으로 사용 (표준적으로 단일)
                return str(ans.rrset[0].target).rstrip(".")
            # NoAnswer인 경우 NXDOMAIN일 수도 있으니 None
            return None
        except (dns.exception.DNSException, Exception):
            return None

    async def query_cname(self, fqdn: str) -> Tuple[bool, str]:
        """CNAME 조회 (재시도 & 다중 리졸버). 결과: (성공여부, actual or 에러 메시지)"""
        fqdn_norm = norm_name(fqdn)
        if fqdn_norm in self.cache:
            return self.cache[fqdn_norm]

        async with self.sem:
            last_err = "no answer"
            for attempt in range(self.retries + 1):
                for ip in self.resolvers:
                    cname = await self.query_cname_once(fqdn, ip)
                    if cname:
                        res = (True, cname)
                        self.cache[fqdn_norm] = res
                        return res
                    else:
                        last_err = f"no answer @{ip}"
                await asyncio.sleep(0)  # yield

            res = (False, last_err)
            self.cache[fqdn_norm] = res
            return res

async def process_file(
    checker: CNAMEChecker,
    csv_path: str,
    origin: Optional[str],
) -> pd.DataFrame:
    rows = []
    # 빠른 csv reader (pandas 대신 표준 csv로 파싱 후 DataFrame 변환)
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"Label/Name", "Type", "R Data"}
        if not required.issubset(reader.fieldnames or []):
            raise RuntimeError(f"{csv_path}: CSV 헤더에 {required} 가 필요합니다. 현재: {reader.fieldnames}")

        tasks = []
        items: List[Tuple[str, str, str]] = []  # (fqdn, expected, rawname)

        for line in reader:
            if (line.get("Type") or "").strip().upper() != "CNAME":
                continue
            raw_name = (line.get("Label/Name") or "").strip()
            expected = (line.get("R Data") or "").strip()
            fqdn = maybe_join_origin(raw_name, origin)
            # expected 끝 점 제거 (비교편의)
            expected_norm = norm_name(expected)
            items.append((fqdn, expected_norm, raw_name))
            tasks.append(checker.query_cname(fqdn))

    results = await asyncio.gather(*tasks)

    for (fqdn, expected_norm, raw_name), (ok, actual_or_err) in zip(items, results):
        fqdn_norm = norm_name(fqdn)
        if ok:
            actual_norm = norm_name(actual_or_err)
            match = (actual_norm == expected_norm)
            status = "OK" if match else "MISMATCH"
            rows.append({
                "source_csv": csv_path,
                "origin": origin or "",
                "label_or_name": raw_name,
                "fqdn": fqdn_norm,
                "expected": expected_norm,
                "actual": actual_norm,
                "status": status,
            })
        else:
            rows.append({
                "source_csv": csv_path,
                "origin": origin or "",
                "label_or_name": raw_name,
                "fqdn": fqdn_norm,
                "expected": expected_norm,
                "actual": "",
                "status": f"NO_ANSWER ({actual_or_err})",
            })

    df = pd.DataFrame(rows)
    return df

def choose_origin(csv_path: str, origin_map: Dict[str, str]) -> Optional[str]:
    # 1) origin-map 기반 매칭 (값이 경로 fragment면 포함 여부로 판단)
    for origin, frag in origin_map.items():
        if frag and frag in csv_path:
            return origin
    # 2) 파일명 기반 자동 유추
    guessed = guess_origin_from_path(csv_path)
    return guessed

async def main():
    ap = argparse.ArgumentParser(description="대량 CNAME 정상 여부 확인기 (Async)")
    ap.add_argument("--csv", action="append", required=True, help="검사할 CSV 파일 (여러 번 지정 가능)")
    ap.add_argument("--concurrency", type=int, default=300, help="동시 질의 수 (기본 300)")
    ap.add_argument("--timeout", type=float, default=3.0, help="DNS 질의 타임아웃 초 (기본 3)")
    ap.add_argument("--retries", type=int, default=2, help="재시도 횟수 (기본 2)")
    ap.add_argument("--resolvers", default=",".join(PUBLIC_RESOLVERS),
                    help=f"리졸버 IP 콤마구분 (기본 {','.join(PUBLIC_RESOLVERS)})")
    ap.add_argument("--origin-map", default="",
                    help='origin 매핑, 예: "lgthinq.com=data/lgthinq.com.csv,lge.com=data/lge.com.csv"')
    ap.add_argument("--out", default="", help="출력 CSV 경로(미지정 시 report_타임스탬프.csv)")

    args = ap.parse_args()

    resolvers = [ip.strip() for ip in args.resolvers.split(",") if ip.strip()]
    origin_map = parse_origin_map(args.origin_map) if args.origin_map else {}

    checker = CNAMEChecker(
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
        resolvers=resolvers,
    )

    dfs = []
    for path in args.csv:
        if not os.path.exists(path):
            print(f"[WARN] 파일 없음: {path}", file=sys.stderr)
            continue
        origin = choose_origin(path, origin_map)
        print(f"[INFO] Loading: {path} (origin={origin or 'auto/unknown'})")
        df = await process_file(checker, path, origin)
        dfs.append(df)

    if not dfs:
        print("처리할 데이터가 없습니다.", file=sys.stderr)
        sys.exit(2)

    all_df = pd.concat(dfs, ignore_index=True)

    # 요약
    total = len(all_df)
    ok = int((all_df["status"] == "OK").sum())
    mismatch = int((all_df["status"] == "MISMATCH").sum())
    noans = int((all_df["status"].str.startswith("NO_ANSWER")).sum())

    print("\n==== SUMMARY ====")
    print(f"Total:     {total}")
    print(f"OK:        {ok}")
    print(f"MISMATCH:  {mismatch}")
    print(f"NO_ANSWER: {noans}")

    # 저장
    out = args.out or f"report_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    all_df.to_csv(out, index=False, encoding="utf-8")
    print(f"\nSaved report -> {out}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)

