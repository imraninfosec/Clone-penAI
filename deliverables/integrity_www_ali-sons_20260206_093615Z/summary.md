# Tool Integrity Run: www.ali-sons.com

## Scan IDs
- katana: 260 (completed)
- nikto: 261 (completed)
- nuclei: 262 (completed)
- sqlmap: 263 (completed)

## Findings Counts (from Raw Summary)
- katana: critical=0 high=0 medium=0 low=0 info=1
- nikto: critical=0 high=0 medium=2 low=0 info=1
- nuclei: critical=0 high=0 medium=0 low=0 info=1
- sqlmap: critical=0 high=0 medium=0 low=0 info=1

## Consolidated Reports (Files)
- Combined HTML: `/opt/ai-pentest/deliverables/integrity_www_ali-sons_20260206_093615Z/reports/report_target_ali-sons.com_combined.html`
- Executive HTML: `/opt/ai-pentest/deliverables/integrity_www_ali-sons_20260206_093615Z/reports/report_target_ali-sons.com_executive.html`
- Technical HTML: `/opt/ai-pentest/deliverables/integrity_www_ali-sons_20260206_093615Z/reports/report_target_ali-sons.com_technical.html`

## Consolidated Reports (API URLs, require Basic auth)
- Combined: `http://localhost:8000/api/report/target/ali-sons.com/html`
- Executive: `http://localhost:8000/api/report/target/ali-sons.com/executive_html`
- Technical: `http://localhost:8000/api/report/target/ali-sons.com/technical_html`

## Top Findings (first ~5 lines per tool)

### katana
- [INFO] Endpoint Discovery - 118 Endpoints Discovered :: https://www.ali-sons.com/ar-news/njz-shhd-leed-gold-w-estidama-3-pearls-lmbn-mrkz-lbtkr-m10b https://www.ali-sons.com/ar-news/shrk-asc-tkrwm-mshryaa-lrbaa-l-wl-

### nikto
- [INFO] Scanner Runtime Error :: + ERROR: Error limit (20) reached for host, giving up. Last error: opening stream: ssl connect failed
- [MEDIUM] Deprecated Clickjacking Header Configuration :: + /:X-Frame-Options header is deprecated and was replaced with the Content-Security-Policy HTTP header with the frame-ancestors directive instead. See: https://
- [MEDIUM] Missing MIME Sniffing Protection Header :: + /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. Se

### nuclei
- [INFO] Scan Completed Without Actionable Output :: No scan output captured.

### sqlmap
- [INFO] No SQL Injection Evidence Detected :: SQLMap automated SQL injection checks (level 1, risk 1). Techniques tested: standard SQLMap suite. Form discovery enabled. No injectable parameters were confirm
