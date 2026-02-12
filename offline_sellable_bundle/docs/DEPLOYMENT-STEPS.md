# Deployment Steps (Offline)

1. Copy `offline_sellable_bundle/app/` to target offline server.
2. Install host dependencies (`python3`, `perl`, `uvicorn`, `fastapi`, etc.).
3. Create deployment config from template:
   - `cp .env.offline.example .env.offline`
4. Set customer branding and bootstrap settings in `.env.offline`:
   - `PRODUCT_BRAND_NAME`
   - `PRODUCT_COMPANY_NAME`
   - `PRODUCT_SECURITY_DIVISION`
   - `BOOTSTRAP_ADMIN_USERNAME`
   - Optional: `BOOTSTRAP_ADMIN_PASSWORD`
5. If prebuilt assets are not already present, run:
   - `./scripts/sync_local_prebuilt_assets.sh`
6. Confirm tools are present in `tools/` and at least one `.gguf` in `models/`.
7. Run prerequisite check:
   - `./scripts/verify_offline_requirements.sh`
8. Start service:
   - `./start_offline.sh`
9. If `BOOTSTRAP_ADMIN_PASSWORD` was not set, read generated one-time credentials:
   - `cat data/bootstrap_admin_credentials.txt`
10. Access UI:
   - `http://<server-ip>:8000`
11. Login and complete mandatory password change at first sign-in.
12. Validate report severity distribution rendering after first report generation:
   - Confirm `Critical`, `High`, `Medium`, and `Low / Info` bars all show numeric counts.
   - Confirm no bar exceeds module width (bar widths are normalized/clamped to 100%).
