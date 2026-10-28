# Notes
# - Each certificate version is a separate entry. Use the version filter with the value
#   "-1" to return only the latest version of each certificate.
# - The default limit is 10. Use limit = "-1" to return all matches.
# - All filter values must be strings, for example "true" rather than true.

# List certificates (first 10 by default)
data "ciphertrust_azure_certificate_list" "all" {}

# List all certificates, latest version only
data "ciphertrust_azure_certificate_list" "latest" {
  filters = {
    version = "-1"
    limit   = "-1"
  }
}

# List the certificates of a vault by vault name
data "ciphertrust_azure_certificate_list" "by_vault_name" {
  filters = {
    key_vault = "my-key-vault"
    version   = "-1"
  }
}

# List the certificates of a vault by CipherTrust Manager vault ID, newest first
data "ciphertrust_azure_certificate_list" "by_vault_id" {
  filters = {
    key_vault_id = ciphertrust_azure_vault.vault.id
    version      = "-1"
    sort         = "-createdAt"
  }
}

# Find a certificate by name
data "ciphertrust_azure_certificate_list" "by_name" {
  filters = {
    cert_name = "my-certificate"
    version   = "-1"
  }
}

# List the latest version of each enabled certificate
data "ciphertrust_azure_certificate_list" "enabled_latest" {
  filters = {
    enabled = "true"
    version = "-1"
  }
}

# List certificates uploaded from CipherTrust Manager.
# These have a cert_source of "local". Native certificates have a cert_source of "native".
data "ciphertrust_azure_certificate_list" "uploaded" {
  filters = {
    cert_source = "local"
    version     = "-1"
  }
}

# Find a certificate by the Azure certificate, key or secret identifier of one version
data "ciphertrust_azure_certificate_list" "by_cid" {
  filters = {
    cid = "https://my-key-vault.vault.azure.net/certificates/my-certificate/0123456789abcdef0123456789abcdef"
  }
}

data "ciphertrust_azure_certificate_list" "by_kid" {
  filters = {
    kid = "https://my-key-vault.vault.azure.net/keys/my-certificate/0123456789abcdef0123456789abcdef"
  }
}

data "ciphertrust_azure_certificate_list" "by_sid" {
  filters = {
    sid = "https://my-key-vault.vault.azure.net/secrets/my-certificate/0123456789abcdef0123456789abcdef"
  }
}

# Find the versions of a certificate by backup.
# All versions of a certificate share the same backup. A new backup is made each time
# a version is created, so use the backup of the latest version.
data "ciphertrust_azure_certificate_list" "by_backup" {
  filters = {
    backup = ciphertrust_azure_certificate.latest.backup
  }
}

# Filter by key algorithm.
# The value is case-sensitive. A native certificate keeps the kty it was created with, for example "RSA".
# An uploaded certificate takes its kty from the imported certificate, which can be lowercase, for example "rsa".
data "ciphertrust_azure_certificate_list" "rsa" {
  filters = {
    algorithm = "RSA"
    version   = "-1"
  }
}

output "latest_certificate_names" {
  value = [for c in data.ciphertrust_azure_certificate_list.latest.certificates : c.name]
}
