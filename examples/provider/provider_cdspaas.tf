# CDSPaaS (multi-tenant SaaS) provider configuration.
# Set `tenant` to the tenant name shown in the CDSPaaS web console.
#
# Most resources behave the same as on-prem CipherTrust Manager. The
# following are platform-managed in CDSPaaS and will fail at plan time:
#   - ciphertrust_cluster
#   - ciphertrust_cm_prometheus
#   - ciphertrust_domain
#   - ciphertrust_hsm_root_of_trust_setup
#   - ciphertrust_interface
#   - ciphertrust_license
#   - ciphertrust_ntp
#   - ciphertrust_password_policy
#   - ciphertrust_policies
#   - ciphertrust_policy_attachments
#   - ciphertrust_property
#   - ciphertrust_proxy
#   - ciphertrust_scp_connection
#   - ciphertrust_syslog
#   - ciphertrust_trial_license
#
# ciphertrust_cm_ssh_key is bootstrap-mode-only and CDSPaaS does not expose
# bootstrap, so it is implicitly unavailable as well.

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
