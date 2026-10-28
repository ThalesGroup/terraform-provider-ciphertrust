# Pre-requisites for a PIT backup - an Azure key managed by CipherTrust Manager.
# See the ciphertrust_azure_key resource for how to create the connection,
# vault and key.
#
# Notes
# - Each time the trigger value changes, the resource is replaced and one new
#   backup is created.
# - Destroying the resource does not delete the backup. It remains in
#   CipherTrust Manager and can be used to restore the key.
# - Use one ciphertrust_azure_key_pit_backup resource per key. To take another
#   backup of the same key, change the trigger value.
# - Import is not supported.

# Create a PIT backup of a key
resource "ciphertrust_azure_key_pit_backup" "backup" {
  key_id  = ciphertrust_azure_key.rsa_key.id
  trigger = "initial"
  # Optional
  name        = "rsa-key-backup"
  description = "Backup taken before the upgrade"
}

# Take another backup of the same key by changing the trigger
# resource "ciphertrust_azure_key_pit_backup" "backup" {
#   key_id  = ciphertrust_azure_key.rsa_key.id
#   trigger = "after-upgrade"
# }

# Restore the key into another vault from the backup
resource "ciphertrust_azure_key" "restored_key" {
  vault_id = ciphertrust_azure_vault.other_vault.id
  restore_key = {
    key_id    = ciphertrust_azure_key.rsa_key.id
    backup_id = ciphertrust_azure_key_pit_backup.backup.id
  }
}

output "backup_id" {
  value = ciphertrust_azure_key_pit_backup.backup.id
}
