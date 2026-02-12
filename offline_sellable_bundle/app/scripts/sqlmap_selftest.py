#!/usr/bin/env python3
"""
Local SQLMap regression/self-test for the AI Pentest platform.

This script spins up local HTTP targets and runs the platform's SQLMap scanner against them.
It is intended to validate:
- http/https/www variant discovery (via katana seed + sqlmap_discovery_targets)
- multi-target SQLMap execution and CSV parsing
- findings include precise injection location (URL + parameter)
- soft-block handling (403/401/429) doesn't hard-fail scans

Safety:
- Targets are local only (127.0.0.1), no external scanning.
- SQLMap is run in non-exploit mode by default (platform forces exploit=N).
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


def _quiet_host(name: str) -> str:
    try:
        socket.getaddrinfo(name, None)
        return name
    except Exception:
        return "127.0.0.1"


class _BaseHandler(BaseHTTPRequestHandler):
    server_version = "ai-pentest-selftest/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - BaseHTTPRequestHandler API
        # Keep self-test output focused on scan results.
        return

    def _send(self, code: int, body: str, content_type: str = "text/html") -> None:
        data = (body or "").encode("utf-8", errors="ignore")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass


class VulnAppHandler(_BaseHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server convention
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query or "")

        if parsed.path == "/":
            host = (self.headers.get("Host") or "127.0.0.1").split(":", 1)[0]
            # Include a cross-port link to ensure port scoping prevents drift.
            body = (
                "<html><body>"
                "<h1>AI Pentest SQLMap Selftest</h1>"
                '<a href="/vuln?id=1">vuln</a><br/>'
                '<a href="/safe?id=1">safe</a><br/>'
                '<a href="/blocked?id=1">blocked</a><br/>'
                f'<a href="http://{host}:9002/safe?id=1">other-port</a><br/>'
                "</body></html>"
            )
            return self._send(200, body, "text/html")

        if parsed.path == "/blocked":
            return self._send(403, "Forbidden", "text/plain")

        if parsed.path == "/vuln":
            # Vulnerable: unsafely interpolated parameter inside SQL string.
            id_value = (qs.get("id") or ["1"])[0]
            try:
                cur = self.server.db.cursor()  # type: ignore[attr-defined]
                query = f"SELECT name FROM items WHERE id = '{id_value}'"
                cur.execute(query)
                rows = cur.fetchall()
                return self._send(200, f"OK {rows}", "text/plain")
            except Exception as exc:
                return self._send(500, f"DB error: {exc}", "text/plain")

        if parsed.path == "/safe":
            id_value = (qs.get("id") or ["1"])[0]
            try:
                cur = self.server.db.cursor()  # type: ignore[attr-defined]
                cur.execute("SELECT name FROM items WHERE id = ?", (id_value,))
                rows = cur.fetchall()
                return self._send(200, f"OK {rows}", "text/plain")
            except Exception as exc:
                return self._send(500, f"DB error: {exc}", "text/plain")

        return self._send(404, "Not Found", "text/plain")


class SafeOnlyHandler(_BaseHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server convention
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query or "")

        if parsed.path == "/":
            body = "<html><body><a href=\"/safe?id=1\">safe</a></body></html>"
            return self._send(200, body, "text/html")

        if parsed.path == "/safe":
            id_value = (qs.get("id") or ["1"])[0]
            try:
                cur = self.server.db.cursor()  # type: ignore[attr-defined]
                cur.execute("SELECT name FROM items WHERE id = ?", (id_value,))
                rows = cur.fetchall()
                return self._send(200, f"OK {rows}", "text/plain")
            except Exception as exc:
                return self._send(500, f"DB error: {exc}", "text/plain")

        return self._send(404, "Not Found", "text/plain")


def _start_http_server(port: int, handler_cls: type[BaseHTTPRequestHandler]) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    httpd.daemon_threads = True
    httpd.db = sqlite3.connect(":memory:", check_same_thread=False)  # type: ignore[attr-defined]
    cur = httpd.db.cursor()  # type: ignore[attr-defined]
    cur.execute("CREATE TABLE items (id TEXT PRIMARY KEY, name TEXT NOT NULL)")
    cur.executemany("INSERT INTO items (id, name) VALUES (?, ?)", [("1", "alpha"), ("2", "beta")])
    httpd.db.commit()  # type: ignore[attr-defined]

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def _insert_scan_row(platform_main, *, user_id: int, target: str, tool: str) -> int:
    db = platform_main.get_db()
    cur = db.cursor()
    cur.execute(
        "INSERT INTO scans (user_id, target, tool, status, results) VALUES (?, ?, ?, 'pending', ?)",
        (user_id, target, tool, json.dumps({})),
    )
    scan_id = int(cur.lastrowid)
    db.commit()
    db.close()
    return scan_id


def _fetch_scan(platform_main, scan_id: int) -> dict:
    db = platform_main.get_db()
    cur = db.cursor()
    cur.execute("SELECT id, target, tool, status, results FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    db.close()
    if not row:
        return {}
    results = {}
    try:
        results = json.loads(row["results"] or "{}") if row["results"] else {}
    except Exception:
        results = {}
    return {
        "id": row["id"],
        "target": row["target"],
        "tool": row["tool"],
        "status": row["status"],
        "results": results,
    }


def _print_scan_summary(platform_main, scan: dict) -> None:
    sid = scan.get("id")
    target = scan.get("target")
    status = scan.get("status")
    results = scan.get("results") or {}

    warning = (results.get("warning") or "").strip()
    error = (results.get("error") or "").strip()

    cmd = results.get("command")
    out = results.get("output") or ""
    findings = platform_main.build_findings_from_output(
        "sqlmap",
        out,
        error,
        results.get("target") or target,
        command=cmd,
    )

    highs = [f for f in findings if str(f.get("severity")).lower() == "high"]
    infos = [f for f in findings if str(f.get("severity")).lower() == "info"]

    print(f"\n=== Scan {sid} ===")
    print(f"Target: {target}")
    print(f"Status: {status}")
    if warning:
        print(f"Warning: {warning}")
    if error:
        print(f"Error: {error}")
    if results.get("sqlmap_katana_seed_targets"):
        print(f"Seed targets: {results.get('sqlmap_katana_seed_targets')}")
    if results.get("sqlmap_results_csv_path"):
        print(f"Results CSV: {results.get('sqlmap_results_csv_path')}")

    print(f"Findings: high={len(highs)} info={len(infos)} total={len(findings)}")
    for f in highs[:5]:
        title = f.get("title")
        loc = f.get("location")
        ev = f.get("evidence")
        print(f"- HIGH: {title} @ {loc}")
        if ev:
            print(f"  Evidence: {ev}")


def main() -> int:
    # Keep selftest fast and deterministic.
    os.environ["SQLMAP_PROFILE"] = "balanced"
    os.environ["SQLMAP_MAX_TARGETS"] = "10"
    os.environ["SQLMAP_TIMEOUT"] = "240"
    os.environ["SQLMAP_REQUEST_TIMEOUT"] = "15"
    os.environ["SQLMAP_RETRIES"] = "1"

    os.environ["SQLMAP_SEED_WITH_KATANA"] = "1"
    os.environ["SQLMAP_KATANA_SEED_DURATION"] = "5"
    os.environ["SQLMAP_KATANA_SEED_TIMEOUT_SECONDS"] = "20"
    os.environ["SQLMAP_KATANA_SEED_DEPTH"] = "2"
    os.environ["SQLMAP_KATANA_SEED_RATE_LIMIT"] = "50"
    os.environ["SQLMAP_KATANA_SEED_CONCURRENCY"] = "5"
    os.environ["SQLMAP_SEED_VARIANTS"] = "1"
    os.environ["SQLMAP_SEED_VARIANTS_MAX"] = "4"
    os.environ["KATANA_TIMEOUT"] = "10"

    # Prefer protocol-aware discovery/preflight to reduce wrong-scheme failures.
    os.environ["SQLMAP_PREFLIGHT_HTTP_PROBE"] = "1"
    os.environ["SQLMAP_DISCOVERY_HTTP_PROBE"] = "1"

    # Import platform after env defaults are set.
    root_dir = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root_dir))
    from backend import main as platform_main  # noqa: WPS433 - local import for selftest

    platform_main.init_database()

    httpd1 = _start_http_server(9001, VulnAppHandler)
    httpd2 = _start_http_server(9002, SafeOnlyHandler)
    time.sleep(0.2)

    try:
        host = _quiet_host("127.0.0.1.nip.io")
        www_host = f"www.{host}" if host != "127.0.0.1" else host

        targets = [
            # No scheme: platform will normalize and discovery will try http/https + www/apex variants.
            f"{host}:9001/",
            # Wrong scheme on explicit port: should be auto-corrected by preflight probe.
            f"https://{host}:9001/",
            # WAF/ACL-like soft block (403) should not hard-fail the scan.
            f"http://{host}:9001/blocked?id=1",
            # www host variant (same local server) to validate variant handling.
            f"http://{www_host}:9001/",
            # Separate safe-only target should yield no injection.
            f"http://{host}:9002/",
        ]

        scan_ids = []
        for t in targets:
            sid = _insert_scan_row(platform_main, user_id=1, target=t, tool="sqlmap")
            scan_ids.append(sid)
            asyncio.run(platform_main.run_scan_async(sid, t, "sqlmap"))

        for sid in scan_ids:
            scan = _fetch_scan(platform_main, sid)
            if scan:
                _print_scan_summary(platform_main, scan)
    finally:
        for httpd in (httpd1, httpd2):
            try:
                httpd.shutdown()
            except Exception:
                pass
            try:
                httpd.server_close()
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
