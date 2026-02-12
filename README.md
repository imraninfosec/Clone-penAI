# AI-Pentest-Project

AI-powered penetration testing platform with automated scanning, report generation, posture/compliance reporting, chat-assisted operations, and governance-focused audit controls.

## Current State (Updated February 11, 2026)

### 1) Security and Access Controls
- Role-aware authentication and authorization flows.
- First-login password rotation (`must_change_password`) for non-admin users.
- Step-up password protection (`X-Action-Password`) for sensitive operations:
  - start scan
  - generate report
  - download report
  - chat-driven scan/report actions
- Audit event logging and exportable audit HTML report (`/api/admin/audit/report/html`).

### 2) Scan Orchestration and Reliability
- Standard all-tools execution order:
  - `katana -> nikto -> nuclei -> sqlmap`
- Report findings order standardized to:
  - `katana -> sqlmap -> nuclei -> nikto`
- Stale/orphan scan reconciliation at startup.
- SQLMap reliability improvements:
  - preflight target validation
  - `http/https` and `apex/www` discovery fallback
  - parameter URL extraction from Katana/Nikto artifacts
  - seed crawl fallback when parameterized URLs are missing

### 3) Findings Quality and Report Consistency
- Suppresses SQLMap heuristic/unexploitable indicators from actionable findings.
- Suppresses noisy Nikto remote read-limit runtime lines from finding tables.
- Executive report "High-Level Findings Overview" now aligns with total findings counts.
- Unified finding normalization across executive, technical, combined, posture, and compliance contexts.
- Severity distribution bars now use normalized/clamped width logic (0-100%) so `Critical/High/Medium/Low-Info` counts render consistently without overflow/misalignment.

### 4) Reporting and Governance
- Report outputs:
  - Executive
  - Technical
  - Combined
  - Compliance Summary (target-level)
- Posture summary endpoint: `/api/posture/summary`.
- Compliance report endpoint: `/api/report/target/{target_ref}/compliance_html`.
- Framework mapping in compliance outputs:
  - ISO/IEC 27001
  - SOC 2
  - NIST
  - OWASP
  - CIS Controls
  - UAE IAS

### 5) Frontend and UX
- Reports tab includes dedicated professional `Compliance Summary` card.
- Improved report dropdown placement/visibility in light and dark modes.
- Posture dashboard includes:
  - heat map summary
  - framework alignment cards
  - target risk cards with categorization
  - direct target report actions
- Light-mode polish:
  - cyber-themed login background (no blank white screen)
  - improved loading contrast and legibility
  - improved dragon/logo visibility and contrast

### 6) Data Hygiene Controls
- Placeholder/test targets are excluded from scans/reports/posture/compliance views.

## Deliverables
Primary documentation is in `deliverables/`:
- `AI-Pentest-Technical-Document.html`
- `AI-Pentest-Executive-Presentation.html`
- `AI-Pentest-Beginner-Guide.html`
- `AI-Pentest-Management-Cheat-Sheet.html`
- `STEP-BY-STEP-IMPLEMENTATION.md`
- `TECHNICAL-IMPLEMENTATION-REFERENCE.md`
- `CISO-UPDATE-SUMMARY.md`

Open index page:
- `http://127.0.0.1:8000/static/deliverables.html`

## Backup Utilities
- `scripts/git_backup_once.sh`
- `scripts/git_backup_daemon.sh`
- `scripts/start_git_backup_daemon.sh`
- `scripts/stop_git_backup_daemon.sh`

## Snapshot Backup Flow
1. `git add -A`
2. `git commit -m "backup: full project snapshot with updated docs and deliverables"`
3. `git push origin <branch>`
