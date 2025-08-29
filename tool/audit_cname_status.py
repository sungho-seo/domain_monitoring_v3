#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CNAME 대량 검사기 (비동기, 날짜/도메인별 산출물)
- 스크립트 위치: tool/
- 입력:   ../data/<DATE>/CNAME_*.csv   (예: CNAME_lge.com.csv)
- 출력:   ../data/<DATE>/output/report_<domain>_<DATE>.csv
          (예: report_lge.com_20250829.csv)

CSV 형식: Label/Name,Type,R Data
- Type이 CNAME인 레코드만 검사
- Label/Name이 상대 이름이면 파일명에서 추론한 origin(도메인)을 붙여 FQDN 변환
- 기대값(R Data)과 실제 응답 CNAME이 일치하는지 확인
"""

import argparse
import asyncio
import csv
import datetime as dt
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import dns.asyncresolver
import dns.exception

PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

def norm_name(s: str) -> str:
    return s.strip().rstrip(".").lower()

def maybe_join_origin(label: str, origin: Optional[str]) -> str:
    label = (label or "").strip()
    if not label:
        return label
    # 이미 절대이름이면 마지막 점만 정리
    if label.endswith("."):
        return label
    # TLD가 있으면 절대이름으로 보고 마지막 점 붙임
    if re.search(r"\.[a-zA-Z]{2,}$", label):
        return label + "."
    # 상대이름이면 origin 붙임
    if origin:
        return f"{label}.{origin}."
    return label + "."

class CNAMEChecker:
    def __init__(self, concurrency: int, timeout: float, retries: int, resolvers: List[str]):
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.retries = retries
        self.resolvers = resolvers
        self.cache: Dict[str, Tuple[bool, str]] = {}

    async def _query_once(self, fqdn: str, resolver_ip: str) -> Optional[str]:
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = [resolver_ip]
        r.lifetime = self.timeout
        try:
            ans = await r.resolve(fqdn, "CNAME", raise_on_no_answer=False)
            if ans.rrset:
                return str(ans.rrset[0].target).rstrip(".")
            return None
        except (dns.exception.DNSException, Exception):
            return None

    async def query_cname(self, fqdn: str) -> Tuple[bool, str]:
        key = norm_name(fqdn)
        if key in self.cache:
            return self.cache[key]

        async with self.sem:
            last_err = "no answer"
            for _ in range(self.retries + 1):
                for ip in self.resolvers:
                    cname = await self._query_once(fqdn, ip)
                    if cname:
                        res = (True, cname)
                        self.cache[key] = res
                        return res
                    last_err = f"no answer @{ip}"
                await asyncio.sleep(0)
            res = (False, last_err)
            self.cache[key] = res
            return res

async def process_csv(checker: CNAMEChecker, csv_path: Path, origin: str) -> pd.DataFrame:
    rows = []
    tasks = []
    items: List[Tuple[str, str, str]] = []  # (fqdn, expected_norm, raw_name)

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"Label/Name", "Type", "R Data"}
        if not required.issubset(reader.fieldnames or []):
            raise RuntimeError(f"{csv_path}: CSV 헤더에 {required} 가 필요합니다. 현재: {reader.fieldnames}")

        for line in reader:
            if (line.get("Type") or "").strip().upper() != "CNAME":
                continue
            raw = (line.get("Label/Name") or "").strip()
            expected = norm_name(line.get("R Data") or "")
            fqdn = maybe_join_origin(raw, origin)
            items.append((fqdn, expected, raw))
            tasks.append(checker.query_cname(fqdn))

    results = await asyncio.gather(*tasks)

    for (fqdn, expected, raw), (ok, actual_or_err) in zip(items, results):
        fqdn_norm = norm_name(fqdn)
        if ok:
            actual_norm = norm_name(actual_or_err)
            status = "OK" if (actual_norm == expected) else "MISMATCH"
            rows.append({
                "source_csv": str(csv_path),
                "origin": origin,
                "label_or_name": raw,
                "fqdn": fqdn_norm,
                "expected": expected,
                "actual": actual_norm,
                "status": status,
            })
        else:
            rows.append({
                "source_csv": str(csv_path),
                "origin": origin,
                "label_or_name": raw,
                "fqdn": fqdn_norm,
                "expected": expected,
                "actual": "",
                "status": f"NO_ANSWER ({actual_or_err})",
            })

    return pd.DataFrame(rows)

def origin_from_filename(csv_path: Path) -> Optional[str]:
    # 파일명: CNAME_<domain>.csv → <domain> 추출
    name = csv_path.name
    m = re.match(r"CNAME_(.+)\.csv$", name, re.IGNORECASE)
    if m:
        return m.group(1)
    return None

async def run(date: str, concurrency: int, timeout: float, retries: int, resolvers: List[str]) -> None:
    # 경로 구성 (이 스크립트의 상위 ../data/<DATE>/)
    script_dir = Path(__file__).resolve().parent
    data_dir = (script_dir / ".." / "data" / date).resolve()
    if not data_dir.exists():
        print(f"[ERROR] 입력 폴더가 없습니다: {data_dir}", file=sys.stderr)
        sys.exit(2)

    output_dir = data_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    # 대상 CSV 수집
    csv_files = sorted(p for p in data_dir.glob("CNAME_*.csv") if p.is_file())
    if not csv_files:
        print(f"[ERROR] CSV가 없습니다: {data_dir}/CNAME_*.csv", file=sys.stderr)
        sys.exit(2)

    print(f"[INFO] date={date}")
    print(f"[INFO] input dir = {data_dir}")
    print(f"[INFO] output dir= {output_dir}")
    print(f"[INFO] files     = {[p.name for p in csv_files]}")

    checker = CNAMEChecker(concurrency=concurrency, timeout=timeout, retries=retries, resolvers=resolvers)

    # 파일별 처리 및 개별 산출물 저장
    all_df_list: List[pd.DataFrame] = []
    for csv_path in csv_files:
        origin = origin_from_filename(csv_path)
        if not origin:
            print(f"[WARN] 도메인을 파일명에서 추출하지 못함: {csv_path.name} (건너뜀)")
            continue
        print(f"[INFO] Processing {csv_path.name} (origin={origin})")
        df = await process_csv(checker, csv_path, origin)
        all_df_list.append(df)

        # 도메인별 산출물 저장
        out_file = output_dir / f"report_{origin}_{date}.csv"
        df.to_csv(out_file, index=False, encoding="utf-8")
        ok = int((df["status"] == "OK").sum())
        mismatch = int((df["status"] == "MISMATCH").sum())
        noans = int((df["status"].str.startswith("NO_ANSWER")).sum())
        print(f"[DONE] {csv_path.name} -> {out_file.name} | OK:{ok} MISMATCH:{mismatch} NO_ANSWER:{noans}")

    # 옵션: 전체 요약도 1개 저장 (원치 않으면 주석 처리)
    if all_df_list:
        all_df = pd.concat(all_df_list, ignore_index=True)
        summary_file = output_dir / f"summary_all_{date}.csv"
        all_df.to_csv(summary_file, index=False, encoding="utf-8")
        total = len(all_df)
        ok = int((all_df["status"] == "OK").sum())
        mismatch = int((all_df["status"] == "MISMATCH").sum())
        noans = int((all_df["status"].str.startswith("NO_ANSWER")).sum())
        print(f"\n==== SUMMARY ({date}) ====")
        print(f"Total:     {total}")
        print(f"OK:        {ok}")
        print(f"MISMATCH:  {mismatch}")
        print(f"NO_ANSWER: {noans}")
        print(f"[SAVED] {summary_file.name}")

def main():
    ap = argparse.ArgumentParser(description="CNAME 검사 (날짜/도메인별 산출물)")
    ap.add_argument("--date", required=True, help="날짜(YYYYMMDD)")
    ap.add_argument("--concurrency", type=int, default=300, help="동시 질의 수 (기본 300)")
    ap.add_argument("--timeout", type=float, default=3.0, help="DNS 질의 타임아웃 초 (기본 3)")
    ap.add_argument("--retries", type=int, default=2, help="재시도 횟수 (기본 2)")
    ap.add_argument("--resolvers", default=",".join(PUBLIC_RESOLVERS),
                    help=f"리졸버 IP 콤마구분 (기본 {','.join(PUBLIC_RESOLVERS)})")
    args = ap.parse_args()

    resolvers = [ip.strip() for ip in args.resolvers.split(",") if ip.strip()]

    try:
        asyncio.run(run(args.date, args.concurrency, args.timeout, args.retries, resolvers))
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)

if __name__ == "__main__":
    main()
