# Product Branding and Deployment Guide

This guide defines the release procedure for delivering the offline bundle as a company-branded product.

## Scope
- Work only in: `offline_sellable_bundle/app/`
- Keep live platform unchanged
- Output: branded, offline-ready customer package

## 1. Prepare Customer Branding Assets
Place customer assets in:
- `offline_sellable_bundle/app/frontend/branding/`

Required filenames:
- `brand_logo_dark.svg`
- `brand_logo_light.svg`
- `brand_mark_dark.svg`
- `brand_mark_light.svg`
- `brand_avatar.svg`

If filenames are unchanged, frontend and reports use them automatically.

## 2. Configure Product Identity and Bootstrap Admin
From app folder:
```bash
cd /opt/ai-pentest/offline_sellable_bundle/app
cp .env.offline.example .env.offline
```

Set these values in `.env.offline`:
- `PRODUCT_BRAND_NAME`
- `PRODUCT_COMPANY_NAME`
- `PRODUCT_SECURITY_DIVISION`
- `BOOTSTRAP_ADMIN_USERNAME`
- Optional: `BOOTSTRAP_ADMIN_PASSWORD`

Notes:
- If `BOOTSTRAP_ADMIN_PASSWORD` is not set, the system generates a strong one-time password at first startup.
- Generated credentials are saved in:
  - `data/bootstrap_admin_credentials.txt`

## 3. Sync Prebuilt Local LLM and Tools
```bash
cd /opt/ai-pentest/offline_sellable_bundle/app
./scripts/sync_local_prebuilt_assets.sh
```

This syncs local prebuilt assets into the bundle:
- `tools/nuclei`
- `tools/katana`
- `tools/sqlmap/`
- `tools/nikto/`
- `tools/llama-server`
- `models/*.gguf`

## 4. Validate Offline Readiness
```bash
cd /opt/ai-pentest/offline_sellable_bundle/app
./scripts/verify_offline_requirements.sh
```

Expected:
- all required tools: `OK`
- at least one GGUF model: `OK`

## 5. Start and Perform Product UAT
```bash
cd /opt/ai-pentest/offline_sellable_bundle/app
./start_offline.sh
```

If bootstrap password was auto-generated:
```bash
cat data/bootstrap_admin_credentials.txt
```

Login to:
- `http://<server-ip>:8000`

Mandatory:
- complete forced password change on first login

Validate:
- branding in light and dark modes
- login/loading screens
- executive/technical/combined/compliance reports
- scanner workflow and findings visibility

Stop:
```bash
./stop_offline.sh
```

## 6. Build Customer Delivery Package
```bash
cd /opt/ai-pentest/offline_sellable_bundle/app
./scripts/package_offline_release.sh
```

Output:
- `dist/ai-pentest-offline-ready-<timestamp>.tar.gz`

## 7. Customer Deployment Procedure
On customer offline server:
1. Copy and extract package.
2. Install required host dependencies (`python3`, `perl`, and runtime Python packages).
3. Configure `.env.offline` with customer brand and bootstrap values.
4. Run `./scripts/verify_offline_requirements.sh`.
5. Start `./start_offline.sh`.
6. Login with bootstrap credentials and change password immediately.
7. Validate scanning and reporting workflow.

## 8. Security and Release Checklist
- No hardcoded `admin123` credential is used for bootstrap.
- First-login password rotation is enforced before operational actions.
- Admin account is active and role-locked to `admin`.
- Branding assets are replaced and visible in both themes.
- Reports include customer brand/company/division values.
- Backup and restore procedure is tested.
- Access to management UI is restricted to authorized network ranges.
