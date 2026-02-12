# Branding Placeholder Guide

The duplicated offline app includes placeholder assets under:

- `app/frontend/branding/brand_logo_dark.svg`
- `app/frontend/branding/brand_logo_light.svg`
- `app/frontend/branding/brand_mark_dark.svg`
- `app/frontend/branding/brand_mark_light.svg`
- `app/frontend/branding/brand_avatar.svg`

## Replace Strategy
1. Replace files with your customer brand versions, keeping filenames unchanged.
2. If you prefer PNG/JPG logos, update image references in:
   - `app/frontend/index.html`
   - `app/frontend/loading.html`
   - `app/frontend/dashboard.js`
3. Validate in both light and dark modes.
4. Set text branding in `app/.env.offline`:
   - `PRODUCT_BRAND_NAME`
   - `PRODUCT_COMPANY_NAME`
   - `PRODUCT_SECURITY_DIVISION`

## Note
Legacy logo assets in the duplicate (`logo2.*`, `dragon_*`, `kali_*`) are overwritten with placeholders so no original branding is carried into the sellable package.

For end-to-end branding + deployment procedure, see:
- `../docs/PRODUCT-BRANDING-DEPLOYMENT.md`
