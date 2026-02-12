# Offline Workload and Sizing Guide

## Workload Profiles

### 1) Small Team (Pilot)
- Users: 1-5 concurrent
- Scan volume: up to 20 scans/day
- Recommended:
  - 8 vCPU
  - 16 GB RAM
  - 200 GB SSD

### 2) Medium SOC Team
- Users: 5-20 concurrent
- Scan volume: 20-100 scans/day
- Recommended:
  - 16 vCPU
  - 32-64 GB RAM
  - 500 GB SSD

### 3) Enterprise Multi-Team
- Users: 20+ concurrent
- Scan volume: 100+ scans/day
- Recommended:
  - 24-32 vCPU
  - 64-128 GB RAM
  - 1 TB SSD/NVMe

## Offline Runtime Dependencies
- Python 3
- Perl (for Nikto)
- Scanner binaries/folders in `app/tools`
- Local GGUF model in `app/models`

## Operational Guidance
- Keep `data/`, `logs/`, and `reports/` on persistent encrypted storage.
- Run weekly backup + restore validation.
- Rotate admin credentials by policy.
- Keep scanner/template/model updates in controlled maintenance windows.

## Sellable Delivery Checklist
- Replace placeholder branding assets.
- Configure customer-specific policy defaults in `.env.offline`.
- Validate scan/report workflow in customer network.
- Perform UAT with executive, technical, and compliance reporting.
