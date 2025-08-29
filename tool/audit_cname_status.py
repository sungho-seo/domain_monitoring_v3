#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CNAME 대량 검사기 (비동기, 날짜/도메인별 산출물)
- 입력:   ../data/<DATE>/CNAME_*.csv
- 출력:   ../data/<DATE>/output/report_<domain>_<DATE>.csv
- CSV 헤더: Label/Name,Type,R Data

변경점
- source_csv 컬럼 제거
- expected(R Data)가 상대 이름이면 origin 붙여 FQDN으로 확장 후 비교
- 상대 Label/Name도 확실히 origin을 붙이도록 보강
"""

import argparse
import asyncio
import csv
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import dns.asyncresolver
import dns.exception

PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

# ---------- utils ----------
def norm_name(s: str) -> str:
    return (s or "").strip().rstrip(".").lower()

_TLD_RE = re.compile(r"\.[a-zA-Z]{2,}$")

def is_fqdn_like(name: str) -> bool:
    """TLD가 보이면 FQDN 유사로 간주"""
    return bool(_TLD_RE.search(name))

def to_fqdn(name: str, origin: Optional[str]) -> str:
    """
    상대 이름이면 origin을 붙여 절대 이름으로.
    이미 절대 이름이면 마지막 점만 보정.
    """
    n = (name or "").strip()
    if not n:
        return n
    if n.endswith("."):
        return n
    if is_fqdn_like(n):
        return n + "."
    # 한 라벨(ex: sa-web-us) 또는 'xxx.hlp'같은 내부 서브도메인에도 origin을 붙임
    return f"{n}.{origin}." if origin else n + "."

def normalize_expected(expected: str, origin: Optional[str]) -> str:
    """
    CSV의 R Data가 상대 이름(예: 'sa-web-us')이면 origin을 붙여 비교 공정화.
    """
    e = (expected or "").strip().rstrip(".")
    if not e:
        return ""
    if is_fqdn_like(e):
        return e.lower()
    # 상대 이름 → 같은 존으로 간주
    return (f"{e}.{origin}".lower()) if origin else e.lower()

# ---------- DNS checker ----------
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

# ---------- CSV processing ----------
def origin_from_filename(csv_path: Path) -> Optional[str]:
    m = re.match(r"CNAME_(.+)\.csv$", csv_path.name, re.IGNORECASE)
    return m.group(1) if m else None

async def process_csv(checker: CNAMEChecker, csv_path: Path, origin: str) -> pd.DataFrame:
    rows = []
    tasks = []
    items: List[Tuple[str, str, str]] = []  # (fqdn, expected_norm, raw_label)

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"Label/Name", "Type", "R Data"}
        if not required.issubset(reader.fieldnames or []):
            raise RuntimeError(f"{csv_path}: CSV 헤더에 {required} 필요. 현재: {reader.fieldnames}")

        for line in reader:
            if (line.get("Type") or "").strip().upper() != "CNAME":
                continue
            raw = (line.get("Label/Name") or "").strip()
            fqdn = to_fqdn(raw, origin)
            expected_norm = normalize_expected(line.get("R Data") or "", origin)
            items.append((fqdn, expected_norm, raw))
            tasks.append(checker.query_cname(fqdn))

    results = await asyncio.gather(*tasks)

    for (fqdn, expected_norm, raw), (ok, actual_or_err) in zip(items, results):
        if ok:
            actual_norm = norm_name(actual_or_err)
            status = "OK" if (actual_norm == expected_norm) else "MISMATCH"
            rows.append({
                "origin": origin,
                "label_or_name": raw,
                "fqdn": norm_name(fqdn),
                "expected": expected_norm,
                "actual": actual_norm,
                "status": status,
            })
        else:
            rows.append({
                "origin": origin,
                "label_or_name": raw,
                "fqdn": norm_name(fqdn),
                "expected": expected_norm,
                "actual": "",
                "status": f"NO_ANSWER ({actual_or_err})",
            })

    return pd.DataFrame(rows)

async def run(date: str, concurrency: int, timeout: float, retries: int, resolvers: List[str]) -> None:
    base = (Path(__file__).resolve().parent / ".." / "data" / date).resolve()
    if not base.exists():
        print(f"[ERROR] 입력 폴더 없음: {base}", file=sys.stderr)
        sys.exit(2)

    outdir = base / "output"
    outdir.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(p for p in base.glob("CNAME_*.csv") if p.is_file())
    if not csv_files:
        print(f"[ERROR] CSV가 없습니다: {base}/CNAME_*.csv", file=sys.stderr)
        sys.exit(2)

    print(f"[INFO] files: {[p.name for p in csv_files]}")
    checker = CNAMEChecker(concurrency, timeout, retries, resolvers)

    all_df: List[pd.DataFrame] = []
    for p in csv_files:
        origin = origin_from_filename(p) or ""
        if not origin:
            print(f"[WARN] 파일명에서 도메인을 못 읽음: {p.name} (건너뜀)")
            continue
        print(f"[INFO] Processing {p.name} (origin={origin})")
        df = await process_csv(checker, p, origin)
        all_df.append(df)

        # 도메인별 산출물
        outfile = outdir / f"report_{origin}_{date}.csv"
        df.to_csv(outfile, index=False, encoding="utf-8")

        ok = int((df["status"] == "OK").sum())
        mm = int((df["status"] == "MISMATCH").sum())
        na = int((df["status"].str.startswith("NO_ANSWER")).sum())
        print(f"[DONE] {outfile.name} | OK:{ok} MISMATCH:{mm} NO_ANSWER:{na}")

    if all_df:
        summary = pd.concat(all_df, ignore_index=True)
        summary.to_csv(outdir / f"summary_all_{date}.csv", index=False, encoding="utf-8")

def main():
    ap = argparse.ArgumentParser(description="CNAME 검사 (날짜/도메인별 산출물)")
    ap.add_argument("--date", required=True, help="YYYYMMDD")
    ap.add_argument("--concurrency", type=int, default=300)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--resolvers", default=",".join(PUBLIC_RESOLVERS))
    args = ap.parse_args()

    resolvers = [x.strip() for x in args.resolvers.split(",") if x.strip()]
    try:
        asyncio.run(run(args.date, args.concurrency, args.timeout, args.retries, resolvers))
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(130)

if __name__ == "__main__":
    main()
