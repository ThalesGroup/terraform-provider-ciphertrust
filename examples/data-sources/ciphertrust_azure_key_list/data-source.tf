# Notes
# - Each key version is a separate entry. Use the version filter with the value
#   "-1" to return only the latest version of each key.
# - The default limit is 10. Use limit = "-1" to return all matches.
# - All filter values must be strings, for example "true" rather than true.

# List keys (first 10 by default)
data "ciphertrust_azure_key_list" "all" {}

# List all keys, latest version only
data "ciphertrust_azure_key_list" "latest" {
  filters = {
    version = "-1"
    limit   = "-1"
  }
}

# List the keys of a vault by vault name
data "ciphertrust_azure_key_list" "by_vault_name" {
  filters = {
    key_vault = "my-key-vault"
    version   = "-1"
  }
}

# List the keys of a vault by CipherTrust Manager vault ID, sorted by name
data "ciphertrust_azure_key_list" "by_vault_id" {
  filters = {
    key_vault_id = ciphertrust_azure_vault.vault.id
    version      = "-1"
    sort         = "key_name"
  }
}

# List enabled RSA-sized keys
data "ciphertrust_azure_key_list" "enabled_2048" {
  filters = {
    enabled  = "true"
    key_size = "2048"
    version  = "-1"
  }
}

# List keys scheduled for rotation or backup
data "ciphertrust_azure_key_list" "rotation_enabled" {
  filters = {
    rotation_job_enabled = "true"
    version              = "-1"
  }
}

data "ciphertrust_azure_key_list" "by_backup_job" {
  filters = {
    backup_job_config_id = ciphertrust_scheduler.scheduled_backup.id
    version              = "-1"
  }
}

output "latest_key_names" {
  value = [for k in data.ciphertrust_azure_key_list.latest.keys : k.name]
}
