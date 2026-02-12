# Step-by-Step Implementation Guide

Last updated: February 11, 2026

## 1. Baseline Platform Bring-up
1. Prepare host with Python 3, Perl, Chromium, and scanner binaries.
2. Place tool assets under `/opt/ai-pentest/tools/`:
   - `katana`
   - `nuclei` + `nuclei-templates`
   - `nikto/program/nikto.pl`
   - `sqlmap/sqlmap.py`
3. Start the platform:
   - `./start.sh`
4. Verify health:
   - `curl -s -u <user>:<pass> http://127.0.0.1:8000/api/health`

## 2. Authentication, Authorization, and Audit
1. Enable role-aware auth endpoints:
   - `/api/auth/login`
   - `/api/auth/status`
2. Enforce first-login password rotation (`must_change_password`).
3. Add step-up password (`X-Action-Password`) for sensitive actions:
   - scan start
   - report generation/download
   - chat-driven scan/report actions
4. Verify audit coverage:
   - login success/failure
   - password change
   - report/scan action events
   - admin actions
5. Validate audit report endpoint:
   - `/api/admin/audit/report/html`

## 3. Scan Orchestration and Reliability
1. Set all-tools execution order:
   - `katana -> nikto -> nuclei -> sqlmap`
2. Keep report finding order stable:
   - `katana -> sqlmap -> nuclei -> nikto`
3. Implement orphan scan reconciliation on startup to avoid stuck `pending/running` states.
4. Add per-tool timeout controls and runtime sanitization.

## 4. SQLMap Stability and Coverage Hardening
1. Enable SQLMap preflight reachability checks (`prepare_sqlmap_target`).
2. Try endpoint variants automatically:
   - `http/https`
   - apex and `www` host variants
3. Discover parameterized URLs from:
   - latest Katana output file/logs
   - latest Nikto candidate paths
   - optional SQLMap-specific Katana seed crawl
4. Parse SQLMap CSV results when available and prioritize confirmed injections.
5. Classify transport/access failures separately (401/403/404/429/5xx) instead of false vulnerability positives.

## 5. False-Positive and Noise Reduction
1. Suppress non-actionable SQLMap indicators from findings:
   - false positive
   - unexploitable
   - heuristic/potential-only injection indicators
2. Suppress noisy Nikto remote HTTP read-limit warning lines from finding tables.
3. Keep warnings in evidence context when needed, but avoid counting them as vulnerabilities.

## 6. Report Consistency and Quality
1. Generate and persist:
   - Executive report
   - Technical report
   - Combined report
2. Fix executive high-level findings table behavior so counts align with total findings.
3. Normalize severity-bar calculations used in report charts:
   - include `Low + Info` in chart max baseline
   - clamp per-bar width to `<= 100%`
   - keep count labels visible and aligned for all severities
4. Ensure consolidated (target-level) reports refresh when newer scans exist.
5. Keep placeholders/stale template checks to auto-regenerate outdated artifacts.

## 7. Posture and Compliance Reporting Layer
1. Add `/api/posture/summary` for aggregated target risk posture.
2. Add target-level compliance report endpoint:
   - `/api/report/target/{target_ref}/compliance_html`
3. Build compliance output with:
   - posture snapshot
   - heatmap summary
   - framework alignment
   - finding-to-framework mapping
   - remediation appendix
4. Frameworks mapped in report views:
   - ISO/IEC 27001
   - SOC 2
   - NIST
   - OWASP
   - CIS Controls
   - UAE IAS

## 8. Data Hygiene Controls
1. Exclude test placeholder targets from scan/report/posture/compliance views, including:
   - localhost/nip.io test endpoints
   - `https://example.com`
   - `scanme.nmap.org`
   - `http://testphp.vulnweb.com/listproducts.php?cat=1`
2. Remove known placeholder artifacts (`?`, `the`) from production-facing summaries.

## 9. Frontend and UX Delivery
1. Add Reports tab compliance card with professional target selector.
2. Keep dropdown controls aligned and readable in dark/light mode.
3. Add posture dashboard views:
   - heat map summary
   - top target cards
   - framework cards
   - target posture cards with direct report actions
4. Improve light mode:
   - non-blank cyber-themed login background
   - legible loading overlay colors
   - improved dragon/logo visibility and contrast

## 10. Deliverable Packaging
1. Maintain HTML + PDF deliverables:
   - Technical Document
   - Executive Presentation
   - Beginner Guide
   - Management Cheat Sheet
2. Mirror deliverable artifacts to `frontend/` static folder for in-app access.
3. Provide index page:
   - `/static/deliverables.html`

## 11. Validation Checklist
1. Start scans for approved targets and verify tool completion states.
2. Confirm executive/technical/combined/compliance report availability per target.
3. Check that posture summary counts align with report findings.
4. Confirm excluded test targets do not appear in production views.
5. Verify false-positive SQLMap findings are not shown in actionable sections.
6. Verify audit report export and user-management alignment in UI.

## 12. Backup and Recovery
1. Stage all changes: `git add -A`
2. Commit full snapshot with documentation and deliverables.
3. Push to GitHub backup branch.
4. Optionally run backup daemon scripts under `scripts/` for continuous snapshots.
