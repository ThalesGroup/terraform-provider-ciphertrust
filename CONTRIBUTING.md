# Contributing to the CipherTrust Terraform Provider

Thanks for your interest in contributing! We generally accept any change that adds or updates a
Terraform resource or data source in line with the CipherTrust Manager (CM) and CDSPaaS REST APIs.
For anything beyond a small fix, it's best to open an issue first to discuss the approach.

## Getting started

Use HashiCorp's [Plugin Development](https://developer.hashicorp.com/terraform/plugin) guide as a
general reference, especially the
[Provider Design Principles](https://developer.hashicorp.com/terraform/plugin/hashicorp-provider-design-principles).

This provider is built entirely on the
[Terraform Plugin Framework](https://developer.hashicorp.com/terraform/plugin/framework) (not the
legacy `terraform-plugin-sdk/v2`). Resources and data sources live under `internal/provider/`,
grouped by subsystem (`cm/`, `connections/`, `cckm/{aws,oci}/`, `cte/`, and so on).

If you're adding a new resource or data source, follow
[`.claude/indexes/new-resource-recipe.md`](.claude/indexes/new-resource-recipe.md) — it's the
canonical, step-by-step checklist covering the URL constant, schema, registration in `provider.go`,
examples, docs, and tests. `.claude/indexes/conventions.md` documents the house style in more
detail (CRUD skeleton, HTTP client helpers, logging, 404 handling).

## Resource categories

Broadly, resources and data sources fall into three categories:

- **CM / platform** (`internal/provider/cm/`, `internal/provider/connections/`) — everything native
  to CipherTrust Manager itself: users, keys, groups, domains, cluster bootstrap/join, scheduler,
  policies, syslog, NTP, licenses, proxy, password policy, and cloud connection resources
  (AWS/Azure/GCP/OCI/SCP).
- **CTE** (`internal/provider/cte/`) — Transparent Encryption: clients, client groups, guardpoints,
  policies and their rule types, profiles, user/process/resource/signature sets, CSI groups, and the
  LDT group communication service.
- **CCKM** (`internal/provider/cckm/`) — Cloud Key Management, nested by cloud (`aws/`, `oci/`
  today): cloud-native key resources such as KMS keys, BYOK, XKS/CloudHSM custom key stores, vaults,
  and key policies.

`.claude/indexes/subsystems.md` has the full package-by-package breakdown, including shared schema
and helper files for each area.

## Requirements

- Go 1.25.8 or later
- A live CipherTrust Manager or CDSPaaS tenant for acceptance testing

## Building and testing

```bash
make build      # compile ./terraform-provider-ciphertrust
make install    # go install ./...
make fmt        # gofmt -s -w
make lint       # golangci-lint run
make test       # unit tests
make testacc    # acceptance tests, needs a live CipherTrust Manager
make docs       # regenerate docs/ with tfplugindocs
make generate   # run code generators under tools/
```

Acceptance tests create real resources against a real CipherTrust Manager. They run with
`TF_ACC=1` and read connection details from the `CIPHERTRUST_*` environment variables described in
the [README](README.md#provider-configuration).

To try a locally built provider, point Terraform at the binary with a
[development override](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers)
in your `.terraformrc`.

## Before opening a pull request

Run `make fmt`, `make lint` and `make test` and make sure they pass. Then check the following,
since they're the most common gaps we see in review:

1. Resource/data source attributes match the CipherTrust API field names and structure.
2. [`examples/`](examples/) has a `resource.tf` (or `data-source.tf`) for anything new, with at
   least one usage example.
3. `make docs` has been run and the regenerated files under `docs/` are included in the commit.
4. New resources have at least a basic acceptance test: create, update an attribute, and (where
   supported) import.
5. `.claude/indexes/resources.md` or `data-sources.md` is updated with the new constructor.

## Guidelines

A few callouts for issues that come up occasionally:

- **404 on Read or Update:** keep the resource in state (`resp.Diagnostics.AddError`, do not call
  `resp.State.RemoveResource`) unless this is mid-`Delete` of the same resource. See commit
  `43f3b14`.
- **Replication delay:** don't add a manual `time.Sleep` after a write. The `common.Client` helpers
  (`PostData`, `UpdateData`, etc.) already sleep `ReplicationDelay` ms so cluster nodes have time to
  replicate.
- **UUID per call:** generate a fresh `uuid.New().String()` at the top of each CRUD method for
  request/response log correlation, not once at struct-init.
- **Adding a field to an existing schema:** update the plan/state model *and* the JSON model, and
  populate it in `Create`, `Read` and `Update`.
- **Focused unit tests:** one scenario per test function. Add new cases to the existing test file
  for that resource rather than creating a new file.
- **Inline test configuration:** acceptance tests inline the Terraform config directly in the test
  step rather than returning it from a separate function, except for large or heavily reused
  configurations. This keeps the config next to the assertions it's checked against.
- **`make generate` and license headers:** `.copywrite.hcl` enforces HashiCorp SPDX headers, and
  `make generate` can re-add them repo-wide (~400 files) along with unrelated documentation drift.
  Diff the output and prune anything unrelated to your change before committing.

## Documentation

Documentation under `docs/` is generated from the provider schema and the files under
`examples/` by `tfplugindocs`. Run `make docs` after changing a resource or data source schema, and
don't edit `docs/` by hand.

## Submitting changes

The active development branch is **`1.0.1`**, not `main`. Base your branch off `1.0.1` and open
your pull request against it, referencing any related TFIN-* ticket if applicable.

## Reporting issues

For bugs and feature requests, open an issue in this repository. For security vulnerabilities, see
[SECURITY.md](SECURITY.md) instead of opening a public issue.
