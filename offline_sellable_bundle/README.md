# Offline Sellable Bundle

This folder is a **separate, brand-neutral duplicate** of the platform prepared for offline deployment packaging and reseller delivery to IT firms.

It does **not** modify your live project setup.

## What Is Included
- `app/`:
  - Duplicated backend, frontend, reporting templates, and scripts
  - Severity-bar rendering fix for report charts (all severities visible/aligned)
  - Brand placeholders (logos/marks/avatar)
  - Offline startup/stop scripts
  - Offline prerequisite verifier
  - Offline release packager
  - Prebuilt local asset sync helper (`scripts/sync_local_prebuilt_assets.sh`)
- `docs/`:
  - Offline workload sizing and deployment guidance
- `branding/`:
  - Placeholder branding guide for customer-specific replacement

## Quick Start (Offline)
1. Enter app directory:
   - `cd app`
2. Create env file:
   - `cp .env.offline.example .env.offline`
3. Set branding/bootstrap values in `.env.offline` (`PRODUCT_*`, `BOOTSTRAP_*`).
4. Preload local tools + model from this machine:
   - `./scripts/sync_local_prebuilt_assets.sh`
5. Verify prerequisites:
   - `./scripts/verify_offline_requirements.sh`
6. Start platform:
   - `./start_offline.sh`
7. If bootstrap password is auto-generated, read:
   - `cat data/bootstrap_admin_credentials.txt`
8. Login and complete mandatory password change.
9. Stop platform:
   - `./stop_offline.sh`

## Build a Distribution Tarball
From `app/`:
- `./scripts/package_offline_release.sh`

Output is written to `app/dist/`.

## Current Prebuilt State (Local Workspace)
- This workspace already contains prebuilt scanners under `app/tools/` and a GGUF model under `app/models/`.
- Those large runtime binaries are intentionally ignored from git to keep repository history manageable.

## Branding
All product logos in this duplicate are replaced with placeholders.
See `branding/BRANDING-PLACEHOLDER-GUIDE.md`.

## Productization and Deployment
For full company branding and customer deployment workflow, see:
- `docs/PRODUCT-BRANDING-DEPLOYMENT.md`
