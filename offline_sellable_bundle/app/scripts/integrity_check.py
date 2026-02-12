#!/usr/bin/env python3
"""End-to-end integrity check runner for the Security Platform.

What it does:
- Enumerates historical targets from SQLite
- Runs "all tools" scans for each target via /api/chat
- Waits for completion
- Downloads per-scan logs + raw summaries
- Generates and downloads consolidated (target) reports
- Writes a final JSON + Markdown summary bundle

Usage (example):
  INTEGRITY_USER=admin INTEGRITY_PASS='...' python3 scripts/integrity_check.py

Notes:
- Only run against targets you are authorized to test.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE_URL = os.getenv("INTEGRITY_BASE_URL", "http://localhost:8000").rstrip("/")
ROOT_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("INTEGRITY_DB_PATH", str(ROOT_DIR / "data" / "pentest.db")))
OUT_ROOT = Path(os.getenv("INTEGRITY_OUT_ROOT", str(ROOT_DIR / "deliverables")))

USER = os.getenv("INTEGRITY_USER", "").strip()
PASS = os.getenv("INTEGRITY_PASS", "").strip()

SUPPORTED_TOOLS = ("katana", "nikto", "nuclei", "sqlmap")

INVALID_TARGETS = {"?", "the"}

# Optional scoping controls (defense-in-depth; prevents accidental scans of third-party domains).
INCLUDE_TARGET_REGEX = (os.getenv("INTEGRITY_TARGET_REGEX", "") or "").strip()
EXCLUDE_TARGET_REGEX = (os.getenv("INTEGRITY_EXCLUDE_REGEX", "") or "").strip()
MAX_TARGETS = int(os.getenv("INTEGRITY_MAX_TARGETS", "0") or "0")

_include_re = re.compile(INCLUDE_TARGET_REGEX, re.I) if INCLUDE_TARGET_REGEX else None
_exclude_re = re.compile(EXCLUDE_TARGET_REGEX, re.I) if EXCLUDE_TARGET_REGEX else None


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(ts: dt.datetime) -> str:
    return ts.astimezone(dt.timezone.utc).isoformat()


def die(msg: str, code: int = 2) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def api_request(
    method: str,
    path: str,
    *,
    data: dict | None = None,
    timeout: float = 30.0,
    headers: dict | None = None,
    expect_json: bool = True,
):
    url = f"{BASE_URL}{path}"
    req_headers = {"Authorization": basic_auth_header(USER, PASS)}
    if headers:
        req_headers.update(headers)

    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = urllib.request.Request(url, data=body, headers=req_headers, method=method.upper())

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            if not expect_json:
                return text
            return json.loads(text)
    except urllib.error.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
        text = raw.decode("utf-8", errors="replace") if raw else str(e)
        if expect_json:
            try:
                return json.loads(text)
            except Exception:
                return {"_http_error": True, "status": getattr(e, "code", None), "body": text}
        return text
    except Exception as e:
        if expect_json:
            return {"_error": True, "error": str(e)}
        return str(e)


def canonical_target(raw: str) -> str | None:
    t = (raw or "").strip()
    if not t:
        return None
    if t.lower() in INVALID_TARGETS:
        return None
    if t.startswith("http://") or t.startswith("https://"):
        return t
    return f"https://{t}"

def target_host_key(url: str) -> str:
    """Normalize a URL into a host-key used for deduplication (strip scheme and leading www.)."""
    try:
        p = urllib.parse.urlparse(url)
        host = (p.hostname or "").strip().lower()
    except Exception:
        host = ""
    if host.startswith("www."):
        host = host[4:]
    return host or url.strip().lower()


def load_targets_from_history() -> list[str]:
    if not DB_PATH.exists():
        die(f"DB not found: {DB_PATH}")

    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    cur.execute(
        "SELECT target, MAX(created_at) AS last_seen FROM scans "
        "GROUP BY target ORDER BY last_seen DESC"
    )
    rows = cur.fetchall()
    conn.close()

    seen = set()
    seen_hosts = set()
    targets = []
    for target, _last in rows:
        can = canonical_target(target)
        if not can:
            continue
        # Regex filtering is applied on the canonical URL string (scheme + host + path).
        if _exclude_re and _exclude_re.search(can):
            continue
        if _include_re and not _include_re.search(can):
            continue
        host_key = target_host_key(can)
        if host_key and host_key in seen_hosts:
            continue
        if can in seen:
            continue
        seen.add(can)
        if host_key:
            seen_hosts.add(host_key)
        targets.append(can)

    if MAX_TARGETS and MAX_TARGETS > 0:
        return targets[:MAX_TARGETS]
    return targets


def mkdirp(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    mkdirp(path.parent)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, obj) -> None:
    mkdirp(path.parent)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def parse_scan_ids(reply_text: str) -> list[int]:
    # Example: "... katana (ID 252), nikto (ID 253), ..."
    ids = [int(m.group(1)) for m in re.finditer(r"\bID\s+(\d+)\b", reply_text or "")]
    return ids


def scan_all_tools(target: str) -> dict:
    payload = {"message": f"scan {target} with all tools"}
    res = api_request("POST", "/api/chat", data=payload, timeout=60.0, expect_json=True)
    if not isinstance(res, dict) or "reply" not in res:
        return {"ok": False, "error": f"Unexpected response: {res}"}

    reply = str(res.get("reply") or "")
    scan_ids = parse_scan_ids(reply)
    if len(scan_ids) != 4:
        return {"ok": False, "error": f"Could not parse 4 scan IDs from reply: {reply}", "reply": reply}

    # Map scan IDs to tools by assumed order.
    tool_map = dict(zip(SUPPORTED_TOOLS, scan_ids))
    return {"ok": True, "reply": reply, "scan_ids": tool_map}


def list_scans() -> list[dict]:
    res = api_request("GET", "/api/scans", timeout=30.0, expect_json=True)
    if isinstance(res, list):
        return res
    return []


def poll_until_done(scan_ids: list[int], timeout_seconds: int) -> dict[int, dict]:
    deadline = time.time() + timeout_seconds
    last_state = {}

    while True:
        scans = list_scans()
        by_id = {int(s.get("id")): s for s in scans if str(s.get("id", "")).isdigit()}

        states = {}
        pending = []
        for sid in scan_ids:
            s = by_id.get(int(sid))
            if not s:
                pending.append(sid)
                continue
            status = str(s.get("status") or "").lower()
            states[sid] = s
            if status not in ("completed", "failed"):
                pending.append(sid)

        # Minimal progress output.
        if states != last_state:
            summary = []
            for sid in scan_ids:
                st = states.get(sid, {})
                summary.append(f"{sid}:{st.get('status','?')}")
            print(" ".join(summary))
            last_state = states

        if not pending:
            return states

        if time.time() > deadline:
            return states

        time.sleep(5)


def stop_scan(scan_id: int) -> dict:
    return api_request("POST", f"/api/scan/{scan_id}/stop", timeout=15.0, expect_json=True)


def download_text(path: str, timeout: float = 60.0) -> str:
    return api_request("GET", path, timeout=timeout, expect_json=False)


def download_json(path: str, timeout: float = 60.0):
    return api_request("GET", path, timeout=timeout, expect_json=True)


def generate_report_both(scan_id: int) -> dict:
    return api_request(
        "POST",
        f"/api/scan/{scan_id}/report?report_type=both",
        timeout=120.0,
        expect_json=True,
    )


def parse_findings_summary(raw_summary_text: str) -> dict:
    text = raw_summary_text or ""
    # Extract between "Findings Summary:" and "Errors:".
    findings_block = ""
    m = re.search(r"Findings Summary:\n(.*?)(?:\n\nErrors:|\nErrors:)", text, flags=re.S)
    if m:
        findings_block = m.group(1).strip()

    lines = [l.strip() for l in findings_block.splitlines() if l.strip().startswith("-")]

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    extracted = []
    for line in lines:
        sev_m = re.search(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", line, flags=re.I)
        sev = (sev_m.group(1).lower() if sev_m else "info")
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
        extracted.append(line)

    return {"counts": counts, "lines": extracted}


def tool_versions() -> dict:
    # Use /api/health as canonical tool presence; add versions via local binaries if available.
    health = api_request("GET", "/api/health", timeout=30.0, expect_json=True)
    versions = {"health": health}

    def sh(cmd: str) -> str:
        import subprocess

        try:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
            return out.decode("utf-8", errors="replace").strip()
        except Exception as e:
            return f"error: {e}"

    versions["katana"] = sh(f"{ROOT_DIR / 'tools' / 'katana'} -version | tail -n 1")
    versions["nuclei"] = sh(f"{ROOT_DIR / 'tools' / 'nuclei'} -version | head -n 1")
    versions["sqlmap"] = sh(
        f"python3 {ROOT_DIR / 'tools' / 'sqlmap' / 'sqlmap.py'} --version 2>/dev/null | head -n 1"
    )
    versions["nikto"] = sh(
        f"perl {ROOT_DIR / 'tools' / 'nikto' / 'program' / 'nikto.pl'} -Version 2>/dev/null | head -n 2"
    )

    return versions


def main() -> int:
    if not USER or not PASS:
        die("Set INTEGRITY_USER and INTEGRITY_PASS env vars for API auth.")

    start = now_utc()
    stamp = start.strftime("%Y%m%d_%H%M%SZ")
    out_dir = OUT_ROOT / f"integrity_check_{stamp}"
    scans_dir = out_dir / "scans"
    reports_dir = out_dir / "reports"
    mkdirp(scans_dir)
    mkdirp(reports_dir)

    write_json(out_dir / "tool_versions.json", tool_versions())

    targets = load_targets_from_history()
    write_json(out_dir / "targets.json", targets)

    results = {
        "started_at": iso(start),
        "base_url": BASE_URL,
        "targets": [],
    }

    # Target-level timeout: conservative upper bound (minutes) for 4 tools sequential.
    per_target_timeout = int(os.getenv("INTEGRITY_TARGET_TIMEOUT_SECONDS", str(45 * 60)))

    for idx, target in enumerate(targets, 1):
        print(f"\n== [{idx}/{len(targets)}] Target: {target} ==")
        target_rec = {
            "target": target,
            "scan_ids": {},
            "scan_status": {},
            "artifacts": {},
            "findings": {},
        }

        scan_start_res = scan_all_tools(target)
        if not scan_start_res.get("ok"):
            target_rec["error"] = scan_start_res.get("error")
            target_rec["reply"] = scan_start_res.get("reply")
            results["targets"].append(target_rec)
            write_json(out_dir / "results.partial.json", results)
            continue

        target_rec["reply"] = scan_start_res.get("reply")
        scan_ids_map = scan_start_res["scan_ids"]
        target_rec["scan_ids"] = scan_ids_map

        scan_ids = [scan_ids_map[t] for t in SUPPORTED_TOOLS]
        states = poll_until_done(scan_ids, timeout_seconds=per_target_timeout)

        # Stop still-running scans if we hit timeout.
        for sid in scan_ids:
            st = str(states.get(sid, {}).get("status") or "").lower()
            if st and st not in ("completed", "failed"):
                stop_scan(sid)

        # Refresh final states after stop attempts.
        final_states = poll_until_done(scan_ids, timeout_seconds=60)

        for tool, sid in scan_ids_map.items():
            status = final_states.get(sid, {}).get("status")
            target_rec["scan_status"][tool] = status

        # Download per-scan logs and raw summaries.
        for tool, sid in scan_ids_map.items():
            logs = download_json(f"/api/scan/{sid}/logs", timeout=30.0)
            raw = download_text(f"/api/report/{sid}/raw_summary", timeout=60.0)

            logs_path = scans_dir / f"scan_{sid}_{tool}_logs.json"
            raw_path = scans_dir / f"scan_{sid}_{tool}_raw_summary.txt"
            write_json(logs_path, logs)
            write_text(raw_path, raw)

            target_rec["artifacts"].setdefault("scan_logs", {})[tool] = str(logs_path)
            target_rec["artifacts"].setdefault("raw_summaries", {})[tool] = str(raw_path)

            target_rec["findings"][tool] = parse_findings_summary(raw)

        # Generate consolidated report for this target (via report endpoint on one scan).
        primary_scan = scan_ids_map.get("sqlmap") or scan_ids_map.get("nuclei") or scan_ids[0]
        report_res = generate_report_both(int(primary_scan))
        target_rec["report_generate_response"] = report_res

        downloads = None
        if isinstance(report_res, dict):
            downloads = report_res.get("downloads")

        if isinstance(downloads, dict) and downloads.get("combined_html"):
            combined_url = downloads["combined_html"]
            exec_url = downloads.get("executive_html")
            tech_url = downloads.get("technical_html")

            # Extract target ref from URL for filenames.
            ref = "target"
            m = re.search(r"/api/report/target/([^/]+)/html", combined_url)
            if m:
                ref = m.group(1)

            combined_html = download_text(combined_url, timeout=60.0)
            write_text(reports_dir / f"report_target_{ref}.html", combined_html)
            target_rec["artifacts"]["consolidated_combined_html"] = str(reports_dir / f"report_target_{ref}.html")

            if exec_url:
                exec_html = download_text(exec_url, timeout=60.0)
                write_text(reports_dir / f"report_target_{ref}_executive.html", exec_html)
                target_rec["artifacts"]["consolidated_executive_html"] = str(reports_dir / f"report_target_{ref}_executive.html")

            if tech_url:
                tech_html = download_text(tech_url, timeout=60.0)
                write_text(reports_dir / f"report_target_{ref}_technical.html", tech_html)
                target_rec["artifacts"]["consolidated_technical_html"] = str(reports_dir / f"report_target_{ref}_technical.html")
        else:
            target_rec["report_error"] = "Consolidated report download links missing"

        results["targets"].append(target_rec)
        write_json(out_dir / "results.partial.json", results)

    # Final summary.
    end = now_utc()
    results["completed_at"] = iso(end)

    # Aggregate tool integrity stats.
    tool_totals = {t: {"scans": 0, "completed": 0, "failed": 0} for t in SUPPORTED_TOOLS}
    overall_findings = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for t in results["targets"]:
        for tool in SUPPORTED_TOOLS:
            if tool in (t.get("scan_ids") or {}):
                tool_totals[tool]["scans"] += 1
                status = str((t.get("scan_status") or {}).get(tool) or "").lower()
                if status == "completed":
                    tool_totals[tool]["completed"] += 1
                elif status == "failed":
                    tool_totals[tool]["failed"] += 1

            fcounts = ((t.get("findings") or {}).get(tool) or {}).get("counts") or {}
            for sev in overall_findings:
                overall_findings[sev] += int(fcounts.get(sev, 0) or 0)

    results["tool_totals"] = tool_totals
    results["overall_finding_counts"] = overall_findings

    write_json(out_dir / "results.json", results)

    # Markdown summary.
    lines = []
    lines.append("# Security Platform Integrity Check\n")
    lines.append(f"- Started: {results['started_at']}\n- Completed: {results.get('completed_at','')}\n- Base URL: {BASE_URL}\n")

    lines.append("## Tool Integrity Summary")
    for tool in SUPPORTED_TOOLS:
        s = tool_totals[tool]
        lines.append(f"- {tool}: scans={s['scans']} completed={s['completed']} failed={s['failed']}")

    lines.append("\n## Overall Findings (From Raw Summaries)")
    lines.append("- " + ", ".join([f"{k}={overall_findings[k]}" for k in overall_findings]))

    lines.append("\n## Targets")
    for rec in results["targets"]:
        target = rec.get("target")
        lines.append(f"\n### {target}")
        st = rec.get("scan_status") or {}
        lines.append("- Scan status: " + ", ".join([f"{t}:{st.get(t)}" for t in SUPPORTED_TOOLS if t in st]))
        art = rec.get("artifacts") or {}
        if art.get("consolidated_combined_html"):
            lines.append(f"- Consolidated report (combined): `{art['consolidated_combined_html']}`")
        if art.get("consolidated_executive_html"):
            lines.append(f"- Consolidated report (executive): `{art['consolidated_executive_html']}`")
        if art.get("consolidated_technical_html"):
            lines.append(f"- Consolidated report (technical): `{art['consolidated_technical_html']}`")

        # Show a short top-findings preview.
        preview = []
        for tool in SUPPORTED_TOOLS:
            flines = ((rec.get("findings") or {}).get(tool) or {}).get("lines") or []
            for line in flines[:2]:
                preview.append(f"{tool}: {line}")
        if preview:
            lines.append("- Findings preview (top lines):")
            for p in preview[:8]:
                lines.append(f"  - {p}")

    write_text(out_dir / "summary.md", "\n".join(lines) + "\n")

    print(f"\nDONE. Output bundle: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
