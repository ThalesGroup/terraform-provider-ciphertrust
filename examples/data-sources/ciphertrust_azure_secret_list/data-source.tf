# Notes
# - Each secret version is a separate entry. Use the version filter with the value
#   "-1" to return only the latest version of each secret.
# - The default limit is 10. Use limit = "-1" to return all matches.
# - All filter values must be strings, for example "true" rather than true.
# - The secret value is never returned.

# List secrets (first 10 by default)
data "ciphertrust_azure_secret_list" "all" {}

# List all secrets, latest version only
data "ciphertrust_azure_secret_list" "latest" {
  filters = {
    version = "-1"
    limit   = "-1"
  }
}

# List the secrets of a vault by vault name
data "ciphertrust_azure_secret_list" "by_vault_name" {
  filters = {
    key_vault = "my-key-vault"
    version   = "-1"
  }
}

# List the secrets of a vault by CipherTrust Manager vault ID, newest first
data "ciphertrust_azure_secret_list" "by_vault_id" {
  filters = {
    key_vault_id = ciphertrust_azure_vault.vault.id
    version      = "-1"
    sort         = "-createdAt"
  }
}

# Find a secret by name
data "ciphertrust_azure_secret_list" "by_name" {
  filters = {
    secret_name = "my-secret"
    version     = "-1"
  }
}

# List the latest version of each enabled secret
data "ciphertrust_azure_secret_list" "enabled_latest" {
  filters = {
    enabled = "true"
    version = "-1"
  }
}

# List secrets in a region
data "ciphertrust_azure_secret_list" "by_region" {
  filters = {
    region  = "eastus"
    version = "-1"
  }
}

# List secrets that have been deleted in Azure
data "ciphertrust_azure_secret_list" "deleted_in_azure" {
  filters = {
    deleted_in_azure = "true"
  }
}

# Find a secret by the Azure identifier of one version
data "ciphertrust_azure_secret_list" "by_secret_id" {
  filters = {
    secret_id = "https://my-key-vault.vault.azure.net/secrets/my-secret/0123456789abcdef0123456789abcdef"
  }
}

# Find the versions of a secret by backup.
# All versions of a secret share the same backup. A new backup is made each time
# a version is created, so use the backup of the latest version.
data "ciphertrust_azure_secret_list" "by_backup" {
  filters = {
    backup = ciphertrust_azure_secret.latest.backup
  }
}

# List secrets whose tags contain a JSON value
data "ciphertrust_azure_secret_list" "by_tags" {
  filters = {
    tags    = jsonencode({ environment = "test" })
    version = "-1"
  }
}
