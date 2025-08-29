#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit_cname_status.py (FULL, fixed)
- 입력:   ../data/<DATE>/CNAME_*.csv
- 출력:   ../data/<DATE>/output/report_<domain>_<DATE>.csv
          ../data/<DATE>/output/summary_all_<DATE>.csv  (파일명은 필요시 변경)

판정(status):
- OK
- MISMATCH
- NO_ANSWER(PASS)            : DKIM/ACM 등 검증용. 주소 없어도 정상
- NO_ANSWER(CHECK_INTERNAL)  : 내부 네이밍 의심(휴리스틱)
- NO_ANSWER(LIKELY_UNUSED)   : 체인 끝까지 주소 없음 → 방치/삭제 가능성 큼

옵션:
- --verbose                 : 레코드/추적 단위 상세 로그
- --progress-every N        : N건마다 진행률 로그(기본 50). --verbose면 개별 로그 우선
- --no-trace                : 체인 추적 비활성화(라벨 분류만)
- --max-trace-depth         : CNAME 체인 탐색 최대 hop(기본 10)
- --timeout / --retries / --resolvers : DNS 튜닝
"""

import argparse
import asyncio
import csv
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import dns.asyncresolver

# ------------------- 규칙 -------------------
PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

# A/AAAA 없어도 정상인 검증/서명용 패턴
PASS_PATTERNS = [
    r"\._domainkey(\.|$)",            # DKIM selector
    r"dkim\.amazonses\.com$",         # SES DKIM
    r"_amazonses\.",                  # SES 검증용 호스트
    r"acm-validations\.aws$",         # AWS ACM validation
    r"comodoca\.com$",                # Comodo/DigiCert validation
]

# 외부 DNS에서 없을 가능성 높은 내부 네이밍(휴리스틱)
INTERNAL_PATTERNS = [
    r"\.hlp(\.|$)",
    r"\.pcservice(\.|$)",
    r"\.st-",              # staging prefix
    r"\.dev(\.|$)",
    r"\.qa(\.|$)",
]

# ------------------- 유틸 -------------------
_TLD_RE = re.compile(r"\.[a-zA-Z]{2,}$")

def p(msg: str) -> None:
    print(msg, flush=True)

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

def compile_patterns(patterns: List[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]

def origin_from_filename(csv_path: Path) -> Optional[str]:
    m = re.match(r"CNAME_(.+)\.csv$", csv_path.name, re.IGNORECASE)
    return m.group(1) if m else None

# ------------------- DNS -------------------
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

# ------------------- Checker -------------------
class CNAMEChecker:
    def __init__(self,
                 concurrency: int,
                 timeout: float,
                 retries: int,
                 resolvers: List[str],
                 pass_res: List[re.Pattern],
                 internal_res: List[re.Pattern],
                 trace_enabled: bool,
                 max_depth: int,
                 verbose: bool,
                 progress_every: int):
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.retries = retries
        self.dns = AsyncDNS(resolvers, timeout)
        self.cache_cname: Dict[str, Tuple[bool, str]] = {}
        self.pass_res = pass_res
        self.internal_res = internal_res
        self.trace_enabled = trace_enabled
        self.max_depth = max_depth
        self.verbose = verbose
        self.progress_every = progress_every

    def brief(self, name: str, maxlen: int = 96) -> str:
        n = norm_name(name)
        return n if len(n) <= maxlen else n[:maxlen-3] + "..."

    def _is_pass_name(self, name: str) -> bool:
        n = norm_name(name)
        return any(p.search(n) for p in self.pass_res)

    def _is_internal_name(self, name: str) -> bool:
        n = norm_name(name)
        return any(p.search(n) for p in self.internal_res)

    async def query_cname(self, fqdn: str) -> Tuple[bool, str]:
        """CNAME 조회 (재시도 포함). (ok, actual or 'no answer')"""
        key = norm_name(fqdn)
        if key in self.cache_cname:
            return self.cache_cname[key]

        async with self.sem:
            last_err = "no answer"
            for _ in range(self.retries + 1):
                vals = await self.dns.query(fqdn, "CNAME")
                if vals:
                    res = (True, vals[0])
                    self.cache_cname[key] = res
                    return res
            res = (False, last_err)
            self.cache_cname[key] = res
            return res

    async def trace_to_address(self, start_name: str) -> Tuple[str, bool, List[str], int, str]:
        """
        CNAME 체인 추적 (옵션). 최종적으로 주소 존재 여부 판단.
        return: (final_target, has_address, addr_types, addr_count, note)
        note: ADDR_FOUND / NO_ADDR_NO_CNAME / LOOP / DEPTH_EXCEEDED / SKIPPED / DISABLED
        """
        if not self.trace_enabled:
            return (norm_name(start_name), False, [], 0, "DISABLED")

        # PASS/INTERNAL 패턴이면 추적 자체를 생략
        if self._is_pass_name(start_name) or self._is_internal_name(start_name):
            return (norm_name(start_name), False, [], 0, "SKIPPED")

        seen = set()
        current = start_name if start_name.endswith(".") else start_name + "."
        depth = 0

        while depth < self.max_depth:
            depth += 1
            nn = norm_name(current)
            if nn in seen:
                return (nn, False, [], 0, "LOOP")
            seen.add(nn)

            # A/AAAA 먼저
            a_vals = await self.dns.query(current, "A")
            aaaa_vals = await self.dns.query(current, "AAAA")
            addr_types, addrs = [], []
            if a_vals:
                addr_types.append("A"); addrs.extend(a_vals)
            if aaaa_vals:
                addr_types.append("AAAA"); addrs.extend(aaaa_vals)
            if addrs:
                return (nn, True, addr_types, len(addrs), "ADDR_FOUND")

            # 다음 CNAME hop
            cname_vals = await self.dns.query(current, "CNAME")
            if not cname_vals:
                return (nn, False, [], 0, "NO_ADDR_NO_CNAME")
            current = cname_vals[0] if cname_vals[0].endswith(".") else cname_vals[0] + "."

            # 중간 hop이 PASS/INTERNAL 패턴이면 생략 종료
            if self._is_pass_name(current) or self._is_internal_name(current):
                return (norm_name(current), False, [], 0, "SKIPPED")

        return (norm_name(current), False, [], 0, "DEPTH_EXCEEDED")

    def classify_no_answer_label_only(self, fqdn: str, expected: str, label: str) -> str:
        """
        추가 조회 없이 문자열 패턴만으로 세분화.
        (fqdn / expected / label 중 하나라도 PASS/INTERNAL 매칭되면 해당 라벨)
        """
        names = [fqdn, expected, label]
        if any(self._is_pass_name(n) for n in names):
            return "NO_ANSWER(PASS)"
        if any(self._is_internal_name(n) for n in names):
            return "NO_ANSWER(CHECK_INTERNAL)"
        return "NO_ANSWER(LIKELY_UNUSED)"

# ------------------- CSV 처리 -------------------
async def process_csv(checker: CNAMEChecker,
                      csv_path: Path,
                      origin: str) -> pd.DataFrame:

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

    total = len(items)
    p(f"[INFO] {csv_path.name}: querying {total} records...")

    # 1차: CNAME 조회 (as_completed + 인덱스 반환 방식으로 KeyError 방지)
    async def cname_job(i: int, fqdn: str):
        ok, val = await checker.query_cname(fqdn)
        return i, ok, val

    tasks = [asyncio.create_task(cname_job(i, fqdn)) for i, (fqdn, _, _) in enumerate(items)]
    results: List[Tuple[bool, str]] = [None] * total  # type: ignore

    done = 0
    for fut in asyncio.as_completed(tasks):
        i, ok, val = await fut
        results[i] = (ok, val)
        done += 1
        if checker.verbose:
            fqdn_i, _, raw_i = items[i]
            tag = "OK" if ok else "NO_ANSWER"
            extra = f" -> {val}" if ok else ""
            p(f"[CNAME] {done}/{total} {checker.brief(fqdn_i)} {tag}{extra}")
        elif checker.progress_every and (done % checker.progress_every == 0 or done == total):
            p(f"[PROG] {csv_path.name}: {done}/{total}")

    # 1차 결과 정리
    basic_rows = []
    okmm_rows_for_trace: List[Tuple[dict, str]] = []
    for (fqdn, expected_norm, raw), (ok, actual_or_err) in zip(items, results):
        row = {
            "origin": origin,
            "label_or_name": raw,
            "fqdn": norm_name(fqdn),
            "expected": expected_norm,
            "actual": "",
            "status": "",
            "final_target": "",
            "has_address": "",
            "addr_types": "",
            "addr_count": "",
            "trace_note": "",
        }
        if ok:
            actual_norm = norm_name(actual_or_err)
            row["actual"] = actual_norm
            row["status"] = "OK" if (actual_norm == expected_norm) else "MISMATCH"
            okmm_rows_for_trace.append((row, actual_norm))
        else:
            # CNAME 응답 없음 → 문자열 규칙 기반으로 우선 분류
            subtype = checker.classify_no_answer_label_only(fqdn, expected_norm, raw)
            row["status"] = subtype
        basic_rows.append(row)

    # 2차: 체인 추적 (OK/MISMATCH + 필요 시 NO_ANSWER 검증)
    trace_rows: List[dict] = []
    trace_targets: List[str] = []

    # OK/MISMATCH 대상
    for row, target in okmm_rows_for_trace:
        trace_rows.append(row)
        trace_targets.append(target)

    # NO_ANSWER들도 추적하여 주소가 있으면 PASS로 완화
    if checker.trace_enabled:
        for row in basic_rows:
            if row["status"].startswith("NO_ANSWER"):
                trace_rows.append(row)
                trace_targets.append(row["fqdn"])

    async def trace_job(i: int, target: str):
        res = await checker.trace_to_address(target)
        return i, target, res  # (i, target, (final_target, has_addr, addr_types, addr_count, note))

    if trace_targets:
        t_tasks = [asyncio.create_task(trace_job(i, tgt)) for i, tgt in enumerate(trace_targets)]
        t_done = 0
        for fut in asyncio.as_completed(t_tasks):
            i, target, (final_target, has_addr, addr_types, addr_count, note) = await fut
            row = trace_rows[i]

            row["final_target"] = final_target
            row["has_address"] = "True" if has_addr else ("False" if note not in ("SKIPPED", "DISABLED") else "Skipped")
            row["addr_types"] = ",".join(addr_types) if addr_types else ""
            row["addr_count"] = str(addr_count) if addr_count else ""
            row["trace_note"] = note

            # NO_ANSWER인데 실제 주소가 있으면 PASS로 완화
            if row["status"].startswith("NO_ANSWER") and has_addr:
                row["status"] = "NO_ANSWER(PASS)"

            t_done += 1
            if checker.verbose:
                p(f"[TRACE] {t_done}/{len(t_tasks)} {checker.brief(target)} -> {note}"
                  f"{' (A/AAAA)' if has_addr else ''}")
            elif checker.progress_every and (t_done % checker.progress_every == 0 or t_done == len(t_tasks)):
                p(f"[PROG][TRACE] {csv_path.name}: {t_done}/{len(t_tasks)}")

    # 데이터프레임 반환
    return pd.DataFrame(basic_rows)

# ------------------- Runner -------------------
async def run(date: str,
              concurrency: int,
              timeout: float,
              retries: int,
              resolvers: List[str],
              pass_patterns: List[str],
              internal_patterns: List[str],
              enable_trace: bool,
              max_depth: int,
              verbose: bool,
              progress_every: int) -> None:

    script_dir = Path(__file__).resolve().parent
    base = (script_dir / ".." / "data" / date).resolve()
    outdir = base / "output"
    p(f"[BOOT] audit_cname_status (FULL) | date={date}")
    p(f"[PATH] input_dir={base}")
    p(f"[PATH] output_dir={outdir}")

    if not base.exists():
        p(f"[ERROR] 입력 폴더 없음: {base}")
        sys.exit(2)

    csv_files = sorted(p for p in base.glob("CNAME_*.csv") if p.is_file())
    if not csv_files:
        p(f"[ERROR] CSV가 없습니다: {base}/CNAME_*.csv")
        sys.exit(2)

    outdir.mkdir(parents=True, exist_ok=True)
    p(f"[INFO] files={', '.join(x.name for x in csv_files)}")

    checker = CNAMEChecker(
        concurrency=concurrency,
        timeout=timeout,
        retries=retries,
        resolvers=resolvers,
        pass_res=compile_patterns(pass_patterns),
        internal_res=compile_patterns(internal_patterns),
        trace_enabled=enable_trace,
        max_depth=max_depth,
        verbose=verbose,
        progress_every=progress_every,
    )

    all_df: List[pd.DataFrame] = []
    for csv_path in csv_files:
        origin = origin_from_filename(csv_path) or ""
        if not origin:
            p(f"[WARN] 파일명에서 도메인을 못 읽음: {csv_path.name} (건너뜀)")
            continue

        p(f"[WORK] Processing {csv_path.name} (origin={origin})")
        df = await process_csv(checker, csv_path, origin)
        all_df.append(df)

        # ↓ 필요 시 여기서 파일명 규칙만 바꾸세요
        outfile = outdir / f"report_{origin}_{date}.csv"
        df.to_csv(outfile, index=False, encoding="utf-8")
        ok = int((df["status"] == "OK").sum())
        mm = int((df["status"] == "MISMATCH").sum())
        ps = int((df["status"] == "NO_ANSWER(PASS)").sum())
        ci = int((df["status"] == "NO_ANSWER(CHECK_INTERNAL)").sum())
        lu = int((df["status"] == "NO_ANSWER(LIKELY_UNUSED)").sum())
        p(f"[DONE] {outfile.name} | OK:{ok} MISMATCH:{mm} PASS:{ps} INTERNAL?:{ci} LIKELY_UNUSED:{lu}")
        p(f"[SAVE] {outfile}")

    if not all_df:
        p("[ERROR] 처리된 데이터가 없습니다.")
        sys.exit(2)

    summary = pd.concat(all_df, ignore_index=True)
    # ↓ 필요 시 여기서 summary 파일명만 바꾸세요
    sumfile = outdir / f"summary_all_{date}.csv"
    summary.to_csv(sumfile, index=False, encoding="utf-8")

    s_ok = int((summary["status"] == "OK").sum())
    s_mm = int((summary["status"] == "MISMATCH").sum())
    s_ps = int((summary["status"] == "NO_ANSWER(PASS)").sum())
    s_ci = int((summary["status"] == "NO_ANSWER(CHECK_INTERNAL)").sum())
    s_lu = int((summary["status"] == "NO_ANSWER(LIKELY_UNUSED)").sum())
    s_tot = len(summary)

    p("\n==== SUMMARY ({}) ====".format(date))
    p(f"Total:     {s_tot}")
    p(f"OK:        {s_ok}")
    p(f"MISMATCH:  {s_mm}")
    p(f"PASS:      {s_ps}")
    p(f"INTERNAL?: {s_ci}")
    p(f"LIKELY_UNUSED: {s_lu}")
    p(f"[SAVED] {sumfile}")

def main():
    ap = argparse.ArgumentParser(description="Audit CNAME status (FULL, with trace & verbose)")
    ap.add_argument("--date", required=True, help="YYYYMMDD")
    ap.add_argument("--concurrency", type=int, default=300)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--resolvers", default=",".join(PUBLIC_RESOLVERS))
    ap.add_argument("--no-trace", action="store_true", help="체인 추적 비활성화")
    ap.add_argument("--max-trace-depth", type=int, default=10)
    ap.add_argument("--verbose", action="store_true", help="레코드/추적 단위 상세 로그")
    ap.add_argument("--progress-every", type=int, default=50, help="N건마다 진행률 로그")

    args = ap.parse_args()
    resolvers = [x.strip() for x in args.resolvers.split(",") if x.strip()]

    try:
        asyncio.run(run(
            date=args.date,
            concurrency=args.concurrency,
            timeout=args.timeout,
            retries=args.retries,
            resolvers=resolvers,
            pass_patterns=PASS_PATTERNS,
            internal_patterns=INTERNAL_PATTERNS,
            enable_trace=(not args.no_trace),
            max_depth=args.max_trace_depth,
            verbose=args.verbose,
            progress_every=args.progress_every,
        ))
    except KeyboardInterrupt:
        p("\n[INTERRUPTED]")
        sys.exit(130)

if __name__ == "__main__":
    # 강제 줄단위 flush
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    main()
