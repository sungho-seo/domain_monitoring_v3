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
- CNAME 대상(체인)을 추적하여 최종 A/AAAA 존재 여부 확인 (서비스 실주소 종착 검증)
- DKIM/ACM/검증용 CNAME 등은 추적 스킵(오탐 방지)
- 결과 컬럼: origin,label_or_name,fqdn,expected,actual,status,final_target,has_address,addr_types,addr_count,trace_note
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
import dns.rdatatype

PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

# === 예외 패턴 (추적 스킵: A/AAAA가 없어도 정상인 검증/서명용 CNAME들) ===
DEFAULT_TRACE_SKIP_PATTERNS = [
    r"\._domainkey(\.|$)",            # DKIM selector
    r"dkim\.amazonses\.com$",         # SES DKIM
    r"acm-validations\.aws$",         # AWS ACM validation
    r"comodoca\.com$",                # Comodo/DigiCert 계열 검증
    r"dvcert\.com$",                  # 예시: 여타 인증 검증 도메인
    r"_amazonses\.",                  # SES 검증용
]

# ---------- utils ----------
_TLD_RE = re.compile(r"\.[a-zA-Z]{2,}$")

def norm_name(s: str) -> str:
    return (s or "").strip().rstrip(".").lower()

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

def compile_skip_regex(patterns: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]

# ---------- DNS async helper ----------
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
        """
        Return list of string answers (str(...)) or None on no-answer/failure.
        """
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
                # try next resolver
                pass
        return None

# ---------- CNAME checker with trace ----------
class CNAMEChecker:
    def __init__(self, concurrency: int, timeout: float, retries: int, resolvers: List[str],
                 trace_skip_res: List[re.Pattern], trace_enabled: bool = True,
                 max_depth: int = 10):
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.retries = retries
        self.resolvers = resolvers
        self.dns = AsyncDNS(resolvers, timeout)
        self.cache_cname: Dict[str, Tuple[bool, str]] = {}   # fqdn_norm -> (ok, actual_cname or err)
        self.trace_skip_res = trace_skip_res
        self.trace_enabled = trace_enabled
        self.max_depth = max_depth

    async def query_cname_once(self, fqdn: str) -> Optional[str]:
        vals = await self.dns.query(fqdn, "CNAME")
        if vals:
            # 정상적으로는 단일 CNAME
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

    def _should_skip_trace(self, name: str) -> bool:
        n = norm_name(name)
        return any(p.search(n) for p in self.trace_skip_res)

    async def trace_to_address(self, start_name: str) -> Tuple[str, bool, List[str], int, str]:
        """
        CNAME 체인을 따라가 최종적으로 A/AAAA가 존재하는지 확인.
        returns: (final_target, has_address, addr_types, addr_count, trace_note)

        - 예외 패턴에 매칭되면 추적 스킵
        - max_depth 보호(루프/비정상 체인 방지)
        """
        # 스킵 규칙
        if not self.trace_enabled or self._should_skip_trace(start_name):
            return (norm_name(start_name), False, [], 0, "SKIPPED")

        seen = set()
        current = start_name if start_name.endswith(".") else start_name + "."
        depth = 0

        while depth < self.max_depth:
            depth += 1
            nn = norm_name(current)
            if nn in seen:
                return (norm_name(current), False, [], 0, "LOOP")
            seen.add(nn)

            # 우선 주소 질의 (A/AAAA)
            a_vals = await self.dns.query(current, "A")
            aaaa_vals = await self.dns.query(current, "AAAA")
            addr_types = []
            addrs: List[str] = []
            if a_vals:
                addr_types.append("A")
                addrs.extend(a_vals)
            if aaaa_vals:
                addr_types.append("AAAA")
                addrs.extend(aaaa_vals)
            if addrs:
                return (norm_name(current), True, addr_types, len(addrs), "ADDR_FOUND")

            # 주소가 없으면 CNAME 이어서 추적
            cname_vals = await self.dns.query(current, "CNAME")
            if not cname_vals:
                # 주소도 없고 CNAME도 없다 → 막다른 길
                return (norm_name(current), False, [], 0, "NO_ADDR_NO_CNAME")

            # 다음 hop (일반적으로 단일 CNAME)
            current = cname_vals[0] if cname_vals[0].endswith(".") else cname_vals[0] + "."

            # 중간 hop이 예외 패턴이면 스킵 종료
            if self._should_skip_trace(current):
                return (norm_name(current), False, [], 0, "SKIPPED")

        return (norm_name(current), False, [], 0, "DEPTH_EXCEEDED")

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

    # 1차 결과 (CNAME 일치 여부)
    basic_rows = []
    for (fqdn, expected_norm, raw), (ok, actual_or_err) in zip(items, results):
        if ok:
            actual_norm = norm_name(actual_or_err)
            status = "OK" if (actual_norm == expected_norm) else "MISMATCH"
            basic_rows.append({
                "origin": origin,
                "label_or_name": raw,
                "fqdn": norm_name(fqdn),
                "expected": expected_norm,
                "actual": actual_norm,
                "status": status,
            })
        else:
            basic_rows.append({
                "origin": origin,
                "label_or_name": raw,
                "fqdn": norm_name(fqdn),
                "expected": expected_norm,
                "actual": "",
                "status": f"NO_ANSWER (no answer)",
            })

    # 2차: CNAME 체인 추적(A/AAAA 존재 확인)
    #  - status가 OK 또는 MISMATCH일 때만 의미가 있으므로 그 대상 위주로 추적
    trace_targets = []
    for r in basic_rows:
        if r["status"] in ("OK", "MISMATCH") and r["actual"]:
            trace_targets.append((r, r["actual"]))  # (row_ref, cname_target)

    trace_tasks = [checker.trace_to_address(target) for _, target in trace_targets]
    trace_results = await asyncio.gather(*trace_tasks)

    # trace 결과 반영
    # (추적 안 한 것들은 기본값 채움)
    row_id = 0
    for r in basic_rows:
        r["final_target"] = ""
        r["has_address"] = ""
        r["addr_types"] = ""
        r["addr_count"] = ""
        r["trace_note"] = ""
        basic_rows[row_id] = r
        row_id += 1

    for (row_ref, _), (final_target, has_addr, addr_types, addr_count, note) in zip(trace_targets, trace_results):
        row_ref["final_target"] = final_target
        row_ref["has_address"] = "True" if has_addr else ("False" if note != "SKIPPED" else "Skipped")
        row_ref["addr_types"] = ",".join(addr_types) if addr_types else ""
        row_ref["addr_count"] = str(addr_count) if addr_count else ""
        row_ref["trace_note"] = note

    return pd.DataFrame(basic_rows)

# ---------- runner ----------
async def run(date: str, concurrency: int, timeout: float, retries: int,
              resolvers: List[str], trace_skip_patterns: List[str],
              enable_trace: bool, max_depth: int) -> None:
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
    skip_res = compile_skip_regex(trace_skip_patterns)
    checker = CNAMEChecker(concurrency, timeout, retries, resolvers, skip_res,
                           trace_enabled=enable_trace, max_depth=max_depth)

    all_df: List[pd.DataFrame] = []
    for p in csv_files:
        origin = origin_from_filename(p) or ""
        if not origin:
            print(f"[WARN] 파일명에서 도메인을 못 읽음: {p.name} (건너뜀)")
            continue
        print(f"[INFO] Processing {p.name} (origin={origin})")
        df = await process_csv(checker, p, origin)
        all_df.append(df)

        outfile = outdir / f"report_{origin}_{date}.csv"
        df.to_csv(outfile, index=False, encoding="utf-8")

        ok = int((df["status"] == "OK").sum())
        mm = int((df["status"] == "MISMATCH").sum())
        na = int((df["status"].str.startswith("NO_ANSWER")).sum())
        print(f"[DONE] {outfile.name} | OK:{ok} MISMATCH:{mm} NO_ANSWER:{na}")

    if all_df:
        summary = pd.concat(all_df, ignore_index=True)
        summary.to_csv(outdir / f"summary_all_{date}.csv", index=False, encoding="utf-8")
        tot = len(summary)
        ok = int((summary["status"] == "OK").sum())
        mm = int((summary["status"] == "MISMATCH").sum())
        na = int((summary["status"].str.startswith("NO_ANSWER")).sum())
        print(f"\n==== SUMMARY ({date}) ====")
        print(f"Total:     {tot}")
        print(f"OK:        {ok}")
        print(f"MISMATCH:  {mm}")
        print(f"NO_ANSWER: {na}")

def main():
    ap = argparse.ArgumentParser(description="CNAME 검사 (날짜/도메인별 산출물 + 최종 A/AAAA 추적)")
    ap.add_argument("--date", required=True, help="YYYYMMDD")
    ap.add_argument("--concurrency", type=int, default=300)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--resolvers", default=",".join(PUBLIC_RESOLVERS))
    ap.add_argument("--max-trace-depth", type=int, default=10,
                    help="CNAME 체인 최대 hop 수 (기본 10)")
    ap.add_argument("--no-trace", action="store_true",
                    help="CNAME 대상 추적(A/AAAA 확인) 비활성화")
    ap.add_argument("--trace-skip-pattern", action="append",
                    help="추적 스킵 정규식(여러 개 지정 가능). 지정 없으면 기본 패턴 사용")

    args = ap.parse_args()

    resolvers = [x.strip() for x in args.resolvers.split(",") if x.strip()]
    if args.trace_skip_pattern:
        patterns = args.trace_skip_pattern
    else:
        patterns = DEFAULT_TRACE_SKIP_PATTERNS

    try:
        asyncio.run(run(
            date=args.date,
            concurrency=args.concurrency,
            timeout=args.timeout,
            retries=args.retries,
            resolvers=resolvers,
            trace_skip_patterns=patterns,
            enable_trace=(not args.no_trace),
            max_depth=args.max_trace_depth,
        ))
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(130)

if __name__ == "__main__":
    main()
