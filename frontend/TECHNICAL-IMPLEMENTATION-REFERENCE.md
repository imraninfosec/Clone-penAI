# Technical Implementation Reference

Last updated: February 11, 2026

## System Layout
- Backend: `backend/main.py` (FastAPI orchestration, auth, scan execution, report generation)
- Frontend: `frontend/index.html`, `frontend/dashboard.js`, `frontend/styles.css`
- Database: `data/pentest.db`
- Reports: `reports/`
- Scanner tools: `tools/`

## Core API Endpoints
- Scan lifecycle
  - `POST /api/scan`
  - `GET /api/scans`
  - `GET /api/scan/{id}`
  - `POST /api/scan/{id}/stop`
- Report generation/download
  - `POST /api/scan/{id}/report?report_type=executive|technical|both`
  - `GET /api/report/{id}/html`
  - `GET /api/report/{id}/executive_html`
  - `GET /api/report/{id}/technical_html`
  - `GET /api/report/target/{target_ref}/html`
  - `GET /api/report/target/{target_ref}/executive_html`
  - `GET /api/report/target/{target_ref}/technical_html`
  - `GET /api/report/target/{target_ref}/compliance_html`
- Posture/compliance summary
  - `GET /api/posture/summary`
- Auth/admin/audit
  - `POST /api/auth/login`
  - `GET /api/auth/status`
  - `POST /api/auth/change-password`
  - `GET /api/admin/audit/report/html`

## Scanner Execution Model
- Supported tools: `katana`, `nikto`, `nuclei`, `sqlmap`
- All-tools run order: `katana -> nikto -> nuclei -> sqlmap`
- Report finding order: `katana -> sqlmap -> nuclei -> nikto`

## SQLMap Reliability Controls
- Target reachability preflight (`prepare_sqlmap_target`)
- Automatic variant attempts:
  - protocol fallback (`http`/`https`)
  - host fallback (`apex`/`www`)
- Parameter URL discovery from:
  - Katana output files
  - Katana output text fallback
  - Nikto parameter candidate extraction
- Optional SQLMap seed crawl with Katana when parameter URLs are not found
- Connection/access errors normalized into operational messages (not false vulnerabilities)

## Finding Normalization Rules
- Non-actionable SQLMap indicators are suppressed from actionable outputs:
  - false positive
  - unexploitable
  - heuristic-only/potential injection lines
- Noisy Nikto runtime read-limit warnings are suppressed from findings tables
- CVSS v4.0 style labels are assigned for consistent severity communication
- Report severity chart widths are normalized against displayed series (`critical`, `high`, `medium`, `low+info`) and clamped to `0-100%` to prevent label loss/misalignment.

## Posture and Compliance Model
- Posture summary aggregates latest scans per target/tool
- Generates:
  - severity distribution
  - risk score and level
  - top risky targets
  - framework-target rollups
- Compliance report includes:
  - posture snapshot
  - heatmap by tool/severity
  - framework mapping cards
  - finding-level mapping table
  - remediation appendix

## Framework Alignment Used
- ISO/IEC 27001
- SOC 2
- NIST
- OWASP
- CIS Controls
- UAE IAS

## Data Hygiene Rules
- Excluded target references are removed from production posture/report views.
- Placeholder entries such as `?` and `the` are blocked from summary views.

## UI Notes
- Reports tab includes dedicated Compliance Summary card.
- Dropdown styling supports dark/light mode visibility.
- Posture tab includes heat map, risk cards, framework cards, and target action cards.
- Light-mode login/loading and dragon branding were contrast-tuned for professional visibility.

## Offline Deployment Notes
- Core platform can run in a closed network if dependencies/tools/models are pre-packaged.
- Internet is mainly needed for optional feed updates, package downloads, and template updates.
