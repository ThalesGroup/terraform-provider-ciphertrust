# Terraform Provider for CipherTrust Manager and CDSPaaS

The CipherTrust provider configures a CipherTrust Manager (CM) instance or cluster, or a CipherTrust Data Security Platform as a Service (CDSPaaS) tenant, and manages cloud key resources protected by these platforms.

- **Registry documentation:** https://registry.terraform.io/providers/ThalesGroup/CipherTrust/latest/docs
- **Resource and data source reference:** [`docs/`](docs/), covering [resources](docs/resources/) and [data sources](docs/data-sources/)
- **Runnable examples:** [`examples/`](examples/) and [`sample-scripts/`](sample-scripts/)
- **Release notes:** [`changelog.md`](changelog.md)

## Using the provider

```terraform
terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "~> 1.0"
    }
  }
}

provider "ciphertrust" {
  address       = "https://cm.example.com"
  username      = "cm-username"
  password      = "cm-password"
  no_ssl_verify = true
}

resource "ciphertrust_cm_key" "example" {
  name      = "example-key"
  algorithm = "aes"
  key_size  = 256
}
```

## Deploying CipherTrust Manager

### AWS

To deploy a Virtual CipherTrust Manager from AWS, you must supply the Amazon Machine Image (AMI),
available on the AWS Marketplace or through the Thales Cloud Provisioning System. Consult the
[AWS provider documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
for details on launching an EC2 instance with the aws provider.

### Azure

1. List the available versions with
   `Get-AzVMImage -location eastus2 -PublisherName thalesdiscplusainc1596561677238 -Offer cm_k170v -sku ciphertrust_manager`.

2. Obtain image information for a particular version with
   `az vm image show --location eastus2 --urn thalesdiscplusainc1596561677238:cm_k170v:ciphertrust_manager:<desired-version>`.
   Under `plan`, obtain the required values for `name`, `product` and `publisher`.

3. Consult the [azurerm provider documentation](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine)
   for details on creating a plan to launch a Linux Virtual Machine with the azurerm provider.

### Google Cloud

1. List the available CipherTrust Manager versions with
   `gcloud compute images list --no-standard-images --project=thales-cpl-public`. CipherTrust
   Manager image names start with the prefix `k170v`. Copy the `NAME` of the image you would like
   to deploy.

2. Consult the [Google Cloud Platform provider documentation](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance)
   for details on launching a Virtual Machine image with the GCP provider.

### Oracle Cloud Infrastructure

Refer to the CipherTrust Manager online documentation to create a CipherTrust Manager instance in
OCI. Consult the [OCI provider documentation](https://registry.terraform.io/providers/oracle/oci/latest/docs)
for details on launching a Compute instance with the oci provider.

## Provider configuration

Every provider parameter can be supplied in three places:

1. The `provider` block in the Terraform configuration
2. An environment variable
3. The configuration file `~/.ciphertrust/config`

They are listed in order of precedence: a value in the provider block wins over an environment
variable, which in turn wins over the configuration file.

All parameters are optional in the provider schema. Requirements are enforced at runtime:
`address`, `username` and `password` must be resolvable from one of the three sources, except in
bootstrap mode where only `address` is needed.

### Parameters

| Parameter               | Environment variable            | Config file key         | Default   | Notes |
|:------------------------|:--------------------------------|:------------------------|:----------|:------|
| `address`               | `CIPHERTRUST_ADDRESS`           | `address`               | —         | HTTPS URL of the CipherTrust instance. Not required when creating a cluster. |
| `username`              | `CIPHERTRUST_USERNAME`          | `username`              | —         | |
| `password`              | `CIPHERTRUST_PASSWORD`          | `password`              | —         | Sensitive. |
| `auth_domain`           | `CIPHERTRUST_AUTH_DOMAIN`       | `auth_domain`           | `""`      | Domain the user was created in. Empty string is the root domain. |
| `domain`                | `CIPHERTRUST_DOMAIN`            | `domain`                | `""`      | Domain to log in to. Empty string is the root domain. |
| `tenant`                | `CIPHERTRUST_TENANT`            | `tenant`                | —         | CDSPaaS only. Opts into the CDSPaaS authentication path. |
| `bootstrap`             | `BOOTSTRAP`                     | `bootstrap`             | `"no"`    | Any value other than `"no"` enables bootstrap mode. |
| `no_ssl_verify`         | `NO_SSL_VERIFY`                 | `no_ssl_verify`         | `false`   | See [TLS verification](#tls-verification). |
| `ca_cert`               | `CIPHERTRUST_CA_CERT`           | `ca_cert`               | —         | Path to a PEM CA bundle. See [TLS verification](#tls-verification). |
| `rest_api_timeout`      | `REST_API_TIMEOUT`              | `rest_api_timeout`      | `180`     | Seconds. |
| `aws_operation_timeout` | —                               | `aws_operation_timeout` | `480`     | Seconds. Some AWS key operations, for example replication, take a while. |
| `oci_operation_timeout` | —                               | `oci_operation_timeout` | `480`     | Seconds. |
| `replication_delay_ms`  | `CIPHERTRUST_REPLICATION_DELAY` | `replication_delay_ms`  | `100`     | Delay after creating a resource, for clusters behind a load balancer. |
| `log_file`              | —                               | `log_file`              | `ctp.log` | Provider log file, written separately from Terraform debug logs. |
| `log_level`             | —                               | `log_level`             | `info`    | One of `debug`, `info`, `warn`, `error`, `off`. |

The generated schema reference, including full descriptions, is in [`docs/index.md`](docs/index.md).

### Provider block

To authenticate to and log in to the root domain:

```terraform
provider "ciphertrust" {
  address  = "cm-address"
  username = "cm-username"
  password = "cm-password"
}
```

To authenticate to and log in to a domain other than root:

```terraform
provider "ciphertrust" {
  address     = "cm-address"
  username    = "cm-username"
  password    = "cm-password"
  auth_domain = "users-auth-domain"
}
```

To authenticate to one domain but log in to a different one:

```terraform
provider "ciphertrust" {
  address     = "cm-address"
  username    = "cm-username"
  password    = "cm-password"
  auth_domain = "users-auth-domain"
  domain      = "a-different-domain"
}
```

### CipherTrust Data Security Platform as a Service (CDSPaaS)

Use `tenant`, not `auth_domain`, to select the CDSPaaS tenant. Setting it routes authentication
through the CDSPaaS multi-tenant path.

```terraform
provider "ciphertrust" {
  address  = "https://api.ciphertrust.cloud"
  username = "admin@acme.com"
  password = "cdsp-tenant-password"
  tenant   = "acme"
}
```

`tenant` accepts a tenant name (`"acme"`) or a tenant path (`"acme/eng/team"`).

`auth_domain` is still accepted for on-prem domain routing, but it is ignored when `tenant` is set,
since the CDSPaaS path derives `auth_domain_path` from `tenant`, which supersedes it. Configuring
both produces a warning at plan time.

The following resources manage infrastructure that CDSPaaS operates on your behalf and are not
available there. Using them against a CDSPaaS tenant fails at plan time:

<table>
<thead><tr><th colspan="3">Resource</th></tr></thead>
<tbody>
<tr><td><code>ciphertrust_cluster</code></td><td><code>ciphertrust_cm_prometheus</code></td><td><code>ciphertrust_domain</code></td></tr>
<tr><td><code>ciphertrust_hsm_root_of_trust_setup</code></td><td><code>ciphertrust_interface</code></td><td><code>ciphertrust_license</code></td></tr>
<tr><td><code>ciphertrust_ntp</code></td><td><code>ciphertrust_password_policy</code></td><td><code>ciphertrust_policies</code></td></tr>
<tr><td><code>ciphertrust_policy_attachments</code></td><td><code>ciphertrust_property</code></td><td><code>ciphertrust_proxy</code></td></tr>
<tr><td><code>ciphertrust_scp_connection</code></td><td><code>ciphertrust_syslog</code></td><td><code>ciphertrust_trial_license</code></td></tr>
</tbody>
</table>

`ciphertrust_cm_ssh_key` requires bootstrap mode, which CDSPaaS does not expose, so it is
unavailable as well.

### Environment variables

```bash
export CIPHERTRUST_ADDRESS=https://cm.example.com
export CIPHERTRUST_USERNAME=cm-username
export CIPHERTRUST_PASSWORD=cm-password
export CIPHERTRUST_AUTH_DOMAIN=cm-auth-domain
export CIPHERTRUST_DOMAIN=cm-domain
export CIPHERTRUST_TENANT=acme                  # CDSPaaS only
export CIPHERTRUST_CA_CERT=/etc/ssl/certs/my-internal-ca.pem
```

With the authentication values in the environment, the provider block can be empty:

```terraform
provider "ciphertrust" {}
```

### Configuration file

Every provider parameter can be read from `~/.ciphertrust/config`. It is a plain `key = value`
file, one parameter per line:

```ini
address = cm-address
username = cm-username
password = cm-password
```

Because the file may hold credentials, the provider refuses to use one that is not adequately
protected and fails with an error when:

- the path is a **symbolic link**, which is rejected to prevent symlink redirect attacks; or
- the file is **readable, writable or executable by group or other**, since the permissions must be
  user-only, for example `0600` or `0400`.

```bash
chmod 600 ~/.ciphertrust/config
```

With authentication values in the configuration file, the provider block can be empty:

```terraform
provider "ciphertrust" {}
```

## TLS verification

TLS certificate chain and hostname verification is **enabled by default** (`no_ssl_verify = false`),
and the client negotiates a minimum of TLS 1.2. This became the default in v1.0.1; earlier versions
did not verify certificates.

If the CipherTrust Manager presents a certificate that is not in the system trust store, for example
a private PKI, an internally-issued certificate, or an air-gapped environment, supply the CA bundle:

```terraform
provider "ciphertrust" {
  address  = "https://cm.example.com"
  username = "cm-username"
  password = "cm-password"
  ca_cert  = "/etc/ssl/certs/my-internal-ca.pem"
}
```

The file may contain one or more concatenated PEM certificates. Supplied CAs are *added* to the
system trust store rather than replacing it, so a single configuration can reach both private-CA and
publicly-trusted CipherTrust Managers.

Setting `no_ssl_verify = true` disables verification entirely and exposes connections to
man-in-the-middle attacks. It is intended for local development and testing only; the provider emits
a warning at plan time whenever it is enabled.

## Logging

The provider writes its own log, independently of Terraform's `TF_LOG` output, to the path given by
`log_file` (default `ctp.log` in the working directory) at the level given by `log_level` (default
`info`). Set `log_level = "off"` to disable the file entirely.

The log file is created with mode `0600`, since `debug` level records API request detail.

## Supported clouds

Cloud key management (CCKM) resources are available for:

- Amazon Web Services: KMS keys, BYOK, XKS and CloudHSM custom key stores, key policies, rotation.
- Oracle Cloud Infrastructure: vaults, keys, BYOK keys and versions.

Azure and Google Cloud are supported for **connection management only**
(`ciphertrust_azure_connection`, `ciphertrust_gcp_connection`); this provider does not yet expose
Azure or GCP key resources.

Keys for the above clouds can be sourced from CipherTrust Manager.

## Important limitations

### Validators can block destroy operations

Terraform validates the values in your `.tf` configuration on every run, including
`terraform destroy`, before that configuration is passed along. If your configuration contains
invalid values, destroy will fail before the resource can be removed.

**Example:**

- Created resource with `max_connections = 100`
- Edited config to `max_connections = "invalid"`
- Run `terraform destroy` → validation fails
- Must revert config to a valid value, then destroy will succeed

**Workaround:** run `terraform destroy -refresh=false`, or ensure all attributes in your
configuration have valid values before destroying, even if they differ from the actual resource
state. This is common across Terraform providers that define attribute validators, so it is worth
keeping in mind generally.

## Contributing to the provider

```bash
make build      # compile ./terraform-provider-ciphertrust
make install    # go install ./...
make fmt        # gofmt -s -w
make test       # unit tests
make testacc    # acceptance tests, needs a live CipherTrust Manager
make docs       # regenerate docs/ with tfplugindocs
make generate   # run code generators under tools/
```

Acceptance tests create real resources on a real CipherTrust Manager. They run with `TF_ACC=1` and
read the target from the same `CIPHERTRUST_*` environment variables listed above.

To try a locally built provider, point Terraform at the binary with a
[development override](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers)
in your `.terraformrc`.

## Security

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## License

[MIT](LICENSE)

---

© 2026 Thales Group. All rights reserved.
