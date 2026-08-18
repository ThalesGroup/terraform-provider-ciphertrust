# CipherTrust Provider

The CipherTrust provider configures a CipherTrust Manager (CM) instance or cluster, or a CipherTrust
Data Security Platform as a Service (CDSPaaS) tenant, and manages cloud key resources protected by
these platforms.

## Example Usage

```terraform
terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "~> 1.0"
    }
  }
}

variable "ciphertrust_password" {
  description = "CipherTrust Manager user password. Set via TF_VAR_ciphertrust_password, or omit this variable and use the CIPHERTRUST_PASSWORD environment variable."
  type        = string
  sensitive   = true
}

provider "ciphertrust" {
  address     = "https://ip_or_hostname_of_cm"
  username    = "username"
  password    = var.ciphertrust_password
  auth_domain = "authentication-domain"

  # Optional: PEM-encoded CA bundle for private PKI / internally-issued certs.
  # Use this when CipherTrust Manager presents a certificate that is not in
  # the system trust store (air-gapped, self-issued, internal CA, etc.).
  # ca_cert = "/etc/ssl/certs/my-internal-ca.pem"

  # Optional: disable TLS certificate verification. NOT RECOMMENDED. Use this
  # only for local development or testing, never in production. The provider
  # emits a warning at plan time when this is enabled.
  # no_ssl_verify = true
}
```

```terraform
# CDSPaaS (multi-tenant SaaS) provider configuration.
# Set `tenant` to the tenant name shown in the CDSPaaS web console.

variable "ciphertrust_password" {
  description = "CDSPaaS tenant user password. Set via TF_VAR_ciphertrust_password or omit and use the CIPHERTRUST_PASSWORD environment variable."
  type        = string
  sensitive   = true
}

provider "ciphertrust" {
  address  = "https://api.ciphertrust.cloud"
  username = "tenant-admin@acme.com"
  password = var.ciphertrust_password
  tenant   = "acme"
}
```

## Configuration precedence

Every provider parameter can be supplied in three places, listed highest precedence first:

1. The `provider` block in the Terraform configuration
2. An environment variable
3. The configuration file `~/.ciphertrust/config`

All parameters are optional in the schema. Requirements are enforced at runtime: `address`,
`username` and `password` must be resolvable from one of the three sources, except in bootstrap mode
where only `address` is needed.

## Configuration file

`~/.ciphertrust/config` is a plain `key = value` file, one parameter per line:

```ini
address = cm-address
username = cm-username
password = cm-password
```

Because the file may hold credentials, the provider refuses to use one that is not adequately
protected. It fails with an error when the path is a symbolic link, which is rejected to prevent
symlink redirect attacks, or when the file is readable, writable or executable by group or other.
Restrict it with `chmod 600 ~/.ciphertrust/config`.

## TLS verification

Certificate chain and hostname verification is enabled by default (`no_ssl_verify = false`), and the
client negotiates a minimum of TLS 1.2. This became the default in v1.0.1; earlier versions did not
verify certificates.

If the CipherTrust Manager presents a certificate that is not in the system trust store, for example
a private PKI, an internally-issued certificate, or an air-gapped environment, set `ca_cert` to a PEM
bundle. The file may contain one or more concatenated PEM certificates, and supplied CAs are added to
the system trust store rather than replacing it.

Setting `no_ssl_verify = true` disables verification entirely and exposes connections to
man-in-the-middle attacks. It is intended for local development and testing only; the provider emits
a warning at plan time whenever it is enabled.

## Logging

The provider writes its own log, independently of Terraform's `TF_LOG` output, to the path given by
`log_file` (default `ctp.log` in the working directory) at the level given by `log_level` (default
`info`). Set `log_level = "off"` to disable the file entirely. The log file is created with mode
`0600`, since `debug` level records API request detail.

## CDSPaaS

Set `tenant` to select a CDSPaaS tenant, which routes authentication through the CDSPaaS
multi-tenant path. It accepts a tenant name (`"acme"`) or a tenant path (`"acme/eng/team"`).
`auth_domain` is ignored when `tenant` is set, and configuring both produces a warning at plan time.

Most resources behave the same as on an on-prem CipherTrust Manager, but the following manage
CipherTrust Manager infrastructure that CDSPaaS operates on your behalf, so using them against a
CDSPaaS tenant fails at plan time:

<table>
<thead><tr><th colspan="3">Resource</th></tr></thead>
<tbody>
<tr><td><code>ciphertrust_aws_key_material</code></td><td><code>ciphertrust_cluster</code></td><td><code>ciphertrust_cm_prometheus</code></td></tr>
<tr><td><code>ciphertrust_domain</code></td><td><code>ciphertrust_hsm_root_of_trust_setup</code></td><td><code>ciphertrust_interface</code></td></tr>
<tr><td><code>ciphertrust_interface_certificate_renewal</code></td><td><code>ciphertrust_license</code></td><td><code>ciphertrust_ntp</code></td></tr>
<tr><td><code>ciphertrust_password_policy</code></td><td><code>ciphertrust_policies</code></td><td><code>ciphertrust_policy_attachments</code></td></tr>
<tr><td><code>ciphertrust_property</code></td><td><code>ciphertrust_proxy</code></td><td><code>ciphertrust_scp_connection</code></td></tr>
<tr><td><code>ciphertrust_syslog</code></td><td><code>ciphertrust_trial_license</code></td><td></td></tr>
</tbody>
</table>

`ciphertrust_cm_ssh_key` requires bootstrap mode, which CDSPaaS does not expose, so it is
unavailable as well.

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `address` (String) HTTPS URL of the CipherTrust instance. An address need not be provided when creating a cluster of CipherTrust instances. address can be set in the provider block, via the CIPHERTRUST_ADDRESS environment variable or in ~/.ciphertrust/config
- `auth_domain` (String) CipherTrust authentication domain of the user. This is the domain where the user was created. auth_domain can be set in the provider block, via the CIPHERTRUST_AUTH_DOMAIN environment variable or in ~/.ciphertrust/config. Default is the empty string (root domain).
- `aws_operation_timeout` (Number) Some AWS key operations, for example, replication, can take some time to complete. This specifies how long to wait for an operation to complete in seconds. aws_operation_timeout can be set in the provider block or in ~/.ciphertrust/config. Default is 480.
- `bootstrap` (String) Is it a bootstrap operation. bootstrap can be set in the provider block, via the BOOTSTRAP environment variable or in ~/.ciphertrust/config
- `ca_cert` (String) Path to a PEM-encoded CA certificate bundle used to validate the CipherTrust server's TLS certificate. Use this for private PKI, internally-issued certificates, or air-gapped environments where the certificate chain is not in the system trust store. The file may contain one or more concatenated PEM certificates. ca_cert can be set in the provider block, via the CIPHERTRUST_CA_CERT environment variable or in ~/.ciphertrust/config
- `domain` (String) CipherTrust domain to log in to. domain can be set in the provider block, via the CIPHERTRUST_DOMAIN environment variable or in ~/.ciphertrust/config. Default is the empty string (root domain).
- `log_file` (String) Path to the provider log file. Provider logs are written separately from Terraform debug logs. log_file can be set in the provider block or in ~/.ciphertrust/config. Default is ctp.log.
- `log_level` (String) Logging level for the provider log file. log_level can be set in the provider block or in ~/.ciphertrust/config. Default is info. Options: debug, info, warn, error, off.
- `no_ssl_verify` (Boolean) Disable TLS certificate chain and hostname verification when set to true. **WARNING:** disabling certificate verification exposes connections to man-in-the-middle attacks and should only be used for local development or testing — never in production. Set to false (the default) to enforce certificate validation; supply a custom CA bundle via `ca_cert` for private PKI or air-gapped environments. no_ssl_verify can be set in the provider block or in ~/.ciphertrust/config. Default is false.
- `oci_operation_timeout` (Number) Some OCI key operations can take some time to complete. This specifies how long to wait for an operation to complete in seconds. oci_operation_timeout can be set in the provider block or in ~/.ciphertrust/config. Default is 480.
- `password` (String, Sensitive) Password of a CipherTrust user. password can be set in the provider block, via the CIPHERTRUST_PASSWORD environment variable or in ~/.ciphertrust/config
- `replication_delay_ms` (Number) In the case of a CipherTrust Manager cluster behind a load balancer a small delay after creating CipherTrust Manager resources may be required to allow for replication to other cluster instances. replication_delay_ms can be set in the provider block, via the CIPHERTRUST_REPLICATION_DELAY environment variable or in ~/.ciphertrust/config. Default is 100.
- `rest_api_timeout` (Number) CipherTrust rest api timeout in seconds. rest_api_timeout can be set in the provider block or in ~/.ciphertrust/config. Default is 180.
- `tenant` (String) CDSPaaS tenant name (e.g. "acme") or tenant path (e.g. "acme/eng/team"). Setting this opts the provider into the CDSPaaS authentication path; leave unset for on-prem CipherTrust Manager. tenant can be set in the provider block, via the CIPHERTRUST_TENANT environment variable or in ~/.ciphertrust/config
