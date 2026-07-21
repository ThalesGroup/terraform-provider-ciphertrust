# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### BREAKING CHANGES

- **TFIN-423**: `ciphertrust_scheduler_list` — the `cckm_key_rotation_params.aws_params` nested block has been removed. Users must update HCL references to the new flat attributes `cckm_key_rotation_params.aws_retain_alias` and `cckm_key_rotation_params.rotate_material`.

### Bug Fixes

- **TFIN-422**: `ciphertrust_scheduler` — `start_date` and `end_date` now accept an empty string (`""`) to clear a previously set value. Previously, the schema regex validator rejected empty strings, making it impossible to clear these fields via Terraform config even though the CM API supports it.
- **TFIN-424**: `ciphertrust_scheduler_list` — `start_date` and `end_date` were previously stored as `time.Time` (producing the zero value `"0001-01-01T00:00:00Z"` when the CM API omitted the field). They are now stored as raw strings from the CM API response or null when absent. No state migration is required — the prior zero-time value was always incorrect.
