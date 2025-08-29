#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CNAME 대량 검사기 (비동기, 날짜/도메인별 산출물)
- 입력:   ../data/<DATE>/CNAME_*.csv
- 출력:   ../data/<DATE>/output/report_<domain>_<DATE>.csv
- CSV 헤더: Label/Name,Type,R Data

개선 사항
- source_csv 컬럼 제거
- expected(R Data)가 상대 이름이면 origin 붙여 FQDN으로 확장 후 비교
- CNAME 대상(체인)을 추적하여 최종 A/AAAA 존재 여부 확인
- DKIM/ACM/검증용 CNAME 등은 추적 스킵 → NO_ANSWER(PASS)
- 내부 전용 네이밍 의심 → NO_ANSWER(CHECK_INTERNAL)
- 그 외 응답 없음 → NO_ANSWER(LIKELY_UNUSED)
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

# === 예외 패턴 (PASS 처리) ===
PASS_PATTERNS = [
    r"\._domainkey(\.|$)",            # DKIM selector
    r"dkim\.amazonses\.com$",         # SES DKIM
    r"acm-validations\.aws$",         # AWS ACM validation
    r"comodoca\.com$",                # Comodo/DigiCert 검증
    r"_amazonses\.",                  # SES 검증
]

# === 내부 전용 네이밍 의심 패턴 ===
INTERNAL_PATTERNS = [
    r"\.hlp(\.|$)",
    r"\.pcservice(\.|$)",
    r"\.st-",          # staging
    r"\.dev(\.|$)",    # dev
    r"\.qa(\.|$)",     # qa
]


# ---------- utils ----------
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


# ---------- DNS helper ----------
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


# ---------- CNAME checker ----------
class CNAMEChecker:
    def __init__(self, concurrency: int, timeout: float, retries: int, resolvers: List[str],
                 pass_res: List[re.Pattern], internal_res: List[re.Pattern]):
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.retries = retries
        self.resolvers = resolvers
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

    async def query_cname_once(self, fqdn: str) -> Optional[str]:
        vals = await self.dns.query(fqdn, "CNAME")
        if vals:
            return vals[0]
        return None

    async def query_cname(self, fqdn: str) -> Tuple[bool, str]:
        key = norm_name(fqdn)
        if key in self.cache_cname:
            return self.cache_cname[key]

        async with self.sem:
            last_err = "no answer"
            for _ in range(self.retries + 1):
                cname = await self.query_cname_once(fqdn)
                if cname:
                    res = (True, cname)
                    self.cache_cname[key] = res
                    return res
                last_err = "no answer"
            res = (False, last_err)
            self.cache_cname[key] = res
            return res

    async def trace_to_address(self, start_name: str) -> Tuple[str, str]:
        """
        CNAME 체인을 따라 최종 A/AAAA 확인
        return: (final_target, status_subtype)
        """
        if self._is_pass(start_name):
            return (norm_name(start_name), "NO_ANSWER(PASS)")

        if self._is_internal(start_name):
            return (norm_name(start_name), "NO_ANSWER(CHECK_INTERNAL)")

        # 추적 시도
        current = start_name if start_name.endswith(".") else start_name + "."
        depth = 0
        seen = set()
        while depth < 10:
            depth += 1
            nn = norm_name(current)
            if nn in seen:
                return (nn, "NO_ANSWER(LIKELY_UNUSED)")
            seen.add(nn)

            a_vals = await self.dns.query(current, "A")
            aaaa_vals = await self.dns.query(current, "AAAA")
            if a_vals or aaaa_vals:
                return (nn, "ADDR_FOUND")

            cname_vals = await self.dns.query(current, "CNAME")
            if not cname_vals:
                return (nn, "NO_ANSWER(LIKELY_UNUSED)")
            current = cname_vals[0]
        return (norm_name(current), "NO_ANSWER(LIKELY_UNUSED)")


# ---------- CSV processing ----------
def origin_from_filename(csv_path: Path) -> Optional[str]:
    m = re.match(r"CNAME_(.+)\.csv$", csv_path.name, re.IGNORECASE)
    return m.group(1) if m else None

async def process_csv(checker: CNAMEChecker, csv_path: Path, origin: str) -> pd.DataFrame:
    rows = []
    tasks = []
    items: List[Tuple[str, str, str]] = []

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
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
            # NO_ANSWER 세분화
            final_target, subtype = await checker.trace_to_address(fqdn)
            rows.append({
                "origin": origin,
                "label_or_name": raw,
                "fqdn": norm_name(fqdn),
                "expected": expected_norm,
                "actual": "",
                "status": subtype,
            })

    return pd.DataFrame(rows)


# ---------- runner ----------
async def run(date: str, concurrency: int, timeout: float, retries: int, resolvers: List[str]) -> None:
    base = (Path(__file__).resolve().parent / ".." / "data" / date).resolve()
    outdir = base / "output"
    outdir.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(p for p in base.glob("CNAME_*.csv"))
    pass_res = compile_patterns(PASS_PATTERNS)
    internal_res = compile_patterns(INTERNAL_PATTERNS)
    checker = CNAMEChecker(concurrency, timeout, retries, resolvers, pass_res, internal_res)

    all_df: List[pd.DataFrame] = []
    for p in csv_files:
        origin = origin_from_filename(p) or ""
        if not origin:
            continue
        df = await process_csv(checker, p, origin)
        all_df.append(df)
        df.to_csv(outdir / f"report_{origin}_{date}.csv", index=False, encoding="utf-8")

    if all_df:
        summary = pd.concat(all_df, ignore_index=True)
        summary.to_csv(outdir / f"summary_all_{date}.csv", index=False, encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", required=True)
    ap.add_argument("--concurrency", type=int, default=300)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--resolvers", default=",".join(PUBLIC_RESOLVERS))
    args = ap.parse_args()

    resolvers = [x.strip() for x in args.resolvers.split(",") if x.strip()]
    asyncio.run(run(args.date, args.concurrency, args.timeout, args.retries, resolvers))


if __name__ == "__main__":
    main()
