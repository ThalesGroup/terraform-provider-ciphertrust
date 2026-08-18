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
