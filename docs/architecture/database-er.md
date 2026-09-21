# Database ER diagram (approved 2026-08-31)

See the approved schema in the project chat. This file is a quick reference for implementation.

## Tables (24)

`users`, `audit_logs`, `devices`, `device_interfaces`, `scan_sessions`, `ports`, `services`, `scan_services`, `vulnerabilities`, `findings`, `cves`, `finding_cves`, `risk_scores`, `risk_factors`, `risk_factor_values`, `risk_history`, `risk_level_thresholds`, `ml_models`, `ml_predictions`, `ai_explanations`, `remediation_actions`, `finding_remediations`, `experiments`, `experiment_results`

## Design rules

- UUID primary keys on major entities
- Append-only scan and risk history (no overwriting previous assessments)
- Risk calculation happens in Python, not in PostgreSQL triggers
- JSONB only for genuinely dynamic structures (evidence, configuration, ML features)
- `finding_cves.cve_id` references `cves.id` (UUID), not the CVE string

## ESP32-02 demo path

`devices` → `scan_sessions` → `scan_services` → `findings` → `risk_scores` → `risk_factor_values` → `ai_explanations`
