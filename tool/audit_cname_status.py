#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit_cname_status.py
- 입력:   ../data/<DATE>/CNAME_*.csv
- 출력:   ../data/<DATE>/output/report_<domain>_<DATE>.csv, summary_all_<DATE>.csv
- CSV 헤더: Label/Name,Type,R Data

status 값:
- OK
- MISMATCH
- NO_ANSWER(PASS)
- NO_ANSWER(CHECK_INTERNAL)
- NO_ANSWER(LIKELY_UNUSED)
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

PASS_PATTERNS = [
    r"\._domainkey(\.|$)",            # DKIM selector
    r"dkim\.amazonses\.com$",         # SES DKIM
    r"acm-validations\.aws$",         # AWS ACM validation
    r"comodoca\.com$",                # Comodo/DigiCert 검증
    r"_amazonses\.",                  # SES 검증
]
INTERNAL_PATTERNS = [
    r"\.hlp(\.|$)",
    r"\.pcservice(\.|$)",
    r"\.st-",          # staging prefix
    r"\.dev(\.|$)",
    r"\.qa(\.|$)",
]

# ---------- util ----------
def p(msg: str):
    print(msg, flush=True)

def norm_name(s: str) -> str:
    return (s or "").strip().rstrip(".").lower()

_TLD_RE = re.compile(r"\.[a-zA-Z]{2,}$")

def is_fqdn_like(name: str) -> bool:
    return bool(_TLD_RE.search(name or ""))

def to_fqdn(name: str, origin: Optional[str]) -> str:
    n = (name or "").strip()
    if not n:
        return n
    if n.endswith("."):
        return n
    if is_fqdn_like(n):
        return n + "."
    return f"{n}.{origin}." if origin else n + "."

def normalize_expected(expected: str, origin: Optional[str]) -> str:
    e = (expected or "").strip().rstrip(".")
    if not e:
        return ""
    if is_fqdn_like(e):
        return e.lower()
    return (f"{e}.{origin}".lower()) if origin else e.lower()

def compile_patterns(patterns: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]

# ---------- DNS ----------
class AsyncDNS:
    def __init__(self, resolvers: List[str], timeout: float):
        self.resolvers = resolvers
        self.timeout = timeout

    def _client(self, ip: str) -> dns.asyncresolver.Resolver:
        r = dns.asyncresolver.Resolver(configure=False)
        r.nameservers = [ip]
        r.lifetime = self.timeout
        return r

    async def query(self, name: str, rtype: str) -> Optional[List[str]]:
        fqdn = name if name.endswith(".") else name + "."
        for ip in self.resolvers:
            try:
                r = self._client(ip)
                ans = await r.resolve(fqdn, rtype, raise_on_no_answer=False)
                if ans and ans.rrset:
                    vals = []
                    for rr in ans.rrset:
                        if rtype.upper() == "CNAME":
                            vals.append(str(rr.target).rstrip("."))
                        elif rtype.upper() in ("A", "AAAA"):
                            vals.append(str(rr.address))
                        else:
                            vals.append(str(rr))
                    return vals
            except Exception:
                pass
        return None

# ---------- Checker ----------
class CNAMEChecker:
    def __init__(self, concurrency: int, timeout: float, retries: int, resolvers: List[str],
                 pass_res, internal_res):
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.retries = retries
        self.dns = AsyncDNS(resolvers, timeout)
        self.cache_cname: Dict[str, Tuple[bool, str]] = {}
        self.pass_res = pass_res
        self.internal_res = internal_res

    def _is_pass(self, name: str) -> bool:
        n = norm_name(name)
        return any(p.search(n) for p in self.pass_res)

    def _is_internal(self, name: str) -> bool:
        n = norm_name(name)
        return any(p.search(n) for p in self.internal_res)

    async def _query_cname_once(self, fqdn: str) -> Optional[str]:
        vals = await self.dns.query(fqdn, "CNAME")
        return vals[0] if vals else None

    async def query_cname(self, fqdn: str) -> Tuple[bool, str]:
        key = norm_name(fqdn)
        if key in self.cache_cname:
            return self.cache_cname[key]

        async with self.sem:
            last_err = "no answer"
            for _ in range(self.retries + 1):
                cname = await self._query_cname_once(fqdn)
                if cname:
                    res = (True, cname)
                    self.cache_cname[key] = res
                    return res
                last_err = "no answer"
            res = (False, last_err)
            self.cache_cname[key] = res
            return res

    async def classify_no_answer(self, fqdn: str) -> str:
        """NO_ANSWER 세분화 → PASS / CHECK_INTERNAL / LIKELY_UNUSED"""
        if self._is_pass(fqdn):
            return "NO_ANSWER(PASS)"
        if self._is_internal(fqdn):
            return "NO_ANSWER(CHECK_INTERNAL)"

        # 체인 추적: 주소 나오면 사실 NO_ANSWER가 아니었을 가능성(리졸버 일시 문제)
        # 주소가 끝내 안 나오면 LIKELY_UNUSED
        current = fqdn if fqdn.endswith(".") else fqdn + "."
        seen = set()
        for _ in range(10):
            nn = norm_name(current)
            if nn in seen:
                return "NO_ANSWER(LIKELY_UNUSED)"
            seen.add(nn)

            a_vals = await self.dns.query(current, "A")
            aaaa_vals = await self.dns.query(current, "AAAA")
            if a_vals or aaaa_vals:
                # 주소가 나왔는데도 원래 CNAME 질의에서 NO_ANSWER였다면, 미묘한 케이스이긴 함.
                # 여기선 굳이 승격하지 않고 LIKELY_UNUSED가 아님을 표시하려면 PASS로 완화할 수도 있지만,
                # 보수적으로 LIKELY_UNUSED는 피하고 OK/MISMATCH 대상이 아니므로 PASS로 표기.
                return "NO_ANSWER(PASS)"

            cname_vals = await self.dns.query(current, "CNAME")
            if not cname_vals:
                return "NO_ANSWER(LIKELY_UNUSED)"
            current = cname_vals[0]
        return "NO_ANSWER(LIKELY_UNUSED)"

# ---------- CSV ----------
def origin_from_filename(csv_path: Path) -> Optional[str]:
    m = re.match(r"CNAME_(.+)\.csv$", csv_path.name, re.IGNORECASE)
    return m.group(1) if m else None

async def process_csv(checker: CNAMEChecker, csv_path: Path, origin: str) -> pd.DataFrame:
    rows = []
    tasks = []
    items: List[Tuple[str, str, str]] = []

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

    p(f"[INFO] {csv_path.name}: querying {len(tasks)} records...")
    results = await asyncio.gather(*tasks)

    out_rows = []
    for (fqdn, expected_norm, raw), (ok, actual_or_err) in zip(items, results):
        if ok:
            actual_norm = norm_name(actual_or_err)
            status = "OK" if (actual_norm == expected_norm) else "MISMATCH"
        else:
            status = await checker.classify_no_answer(fqdn)

        out_rows.append({
            "origin": origin,
            "label_or_name": raw,
            "fqdn": norm_name(fqdn),
            "expected": expected_norm,
            "actual": actual_norm if ok else "",
            "status": status,
        })

    df = pd.DataFrame(out_rows)
    ok = int((df["status"] == "OK").sum())
    mm = int((df["status"] == "MISMATCH").sum())
    pass_n = int((df["status"] == "NO_ANSWER(PASS)").sum())
    ci_n = int((df["status"] == "NO_ANSWER(CHECK_INTERNAL)").sum())
    lu_n = int((df["status"] == "NO_ANSWER(LIKELY_UNUSED)").sum())
    p(f"[DONE] {csv_path.name} | OK:{ok} MISMATCH:{mm} PASS:{pass_n} INTERNAL?:{ci_n} LIKELY_UNUSED:{lu_n}")
    return df

# ---------- runner ----------
async def run(date: str, concurrency: int, timeout: float, retries: int, resolvers: List[str]) -> None:
    script_dir = Path(__file__).resolve().parent
    base = (script_dir / ".." / "data" / date).resolve()
    p(f"[BOOT] audit_cname_status start | date={date}")
    p(f"[PATH] input_dir={base}")

    if not base.exists():
        p(f"[ERROR] 입력 폴더 없음: {base}")
        sys.exit(2)

    csv_files = sorted(p for p in base.glob("CNAME_*.csv") if p.is_file())
    if not csv_files:
        p(f"[ERROR] CSV가 없습니다: {base}/CNAME_*.csv")
        sys.exit(2)

    outdir = base / "output"
    outdir.mkdir(parents=True, exist_ok=True)
    p(f"[PATH] output_dir={outdir}")
    p(f"[INFO] files={', '.join(x.name for x in csv_files)}")

    pass_res = compile_patterns(PASS_PATTERNS)
    internal_res = compile_patterns(INTERNAL_PATTERNS)
    checker = CNAMEChecker(concurrency, timeout, retries, resolvers, pass_res, internal_res)

    all_df: List[pd.DataFrame] = []
    for csv_path in csv_files:
        origin = origin_from_filename(csv_path) or ""
        if not origin:
            p(f"[WARN] 파일명에서 도메인을 못 읽음: {csv_path.name} (건너뜀)")
            continue
        p(f"[WORK] Processing {csv_path.name} (origin={origin})")
        df = await process_csv(checker, csv_path, origin)
        all_df.append(df)
        outfile = outdir / f"report_{origin}_{date}.csv"
        df.to_csv(outfile, index=False, encoding="utf-8")
        p(f"[SAVE] {outfile}")

    if not all_df:
        p("[ERROR] 처리된 데이터가 없습니다.")
        sys.exit(2)

    summary = pd.concat(all_df, ignore_index=True)
    s_ok  = int((summary["status"] == "OK").sum())
    s_mm  = int((summary["status"] == "MISMATCH").sum())
    s_ps  = int((summary["status"] == "NO_ANSWER(PASS)").sum())
    s_ci  = int((summary["status"] == "NO_ANSWER(CHECK_INTERNAL)").sum())
    s_lu  = int((summary["status"] == "NO_ANSWER(LIKELY_UNUSED)").sum())
    s_tot = len(summary)

    sumfile = outdir / f"summary_all_{date}.csv"
    summary.to_csv(sumfile, index=False, encoding="utf-8")

    p("\n==== SUMMARY ({}) ====".format(date))
    p(f"Total:     {s_tot}")
    p(f"OK:        {s_ok}")
    p(f"MISMATCH:  {s_mm}")
    p(f"PASS:      {s_ps}")
    p(f"INTERNAL?: {s_ci}")
    p(f"LIKELY_UNUSED: {s_lu}")
    p(f"[SAVED] {sumfile}")

def main():
    ap = argparse.ArgumentParser(description="Audit CNAME status with NO_ANSWER subtypes")
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
        p("\n[INTERRUPTED]")
        sys.exit(130)

if __name__ == "__main__":
    # 즉시 출력되도록 파이썬 버퍼링 우회 (터미널에서 -u 없이도)
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    main()
