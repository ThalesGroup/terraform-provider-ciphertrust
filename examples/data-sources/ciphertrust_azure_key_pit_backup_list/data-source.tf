# Notes
# - key_id is the CipherTrust Manager resource ID of the key.
# - Backups are sorted newest first by default (sort = "-createdAt").
# - All filter values must be strings.

# List all PIT backups of a key
data "ciphertrust_azure_key_pit_backup_list" "backups" {
  key_id = ciphertrust_azure_key.rsa_key.id
}

# List the PIT backups of a key with filters
data "ciphertrust_azure_key_pit_backup_list" "filtered" {
  key_id = ciphertrust_azure_key.rsa_key.id
  filters = {
    name  = "rsa-key-backup"
    limit = "5"
  }
}

# The newest backup is the first entry. Use it to restore the key.
output "latest_backup_id" {
  value = data.ciphertrust_azure_key_pit_backup_list.backups.backups[0].id
}

resource "ciphertrust_azure_key" "restored_key" {
  vault_id = ciphertrust_azure_vault.other_vault.id
  restore_key = {
    key_id    = ciphertrust_azure_key.rsa_key.id
    backup_id = data.ciphertrust_azure_key_pit_backup_list.backups.backups[0].id
  }
}
