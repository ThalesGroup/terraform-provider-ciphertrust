# Add an Azure Key Vault to CipherTrust Manager.

resource "ciphertrust_azure_connection" "connection" {
  name          = "azure-connection"
  client_id     = "your-client-id"
  tenant_id     = "your-tenant-id"
  client_secret = "your-client-secret"
  products      = ["cckm"]
}

data "ciphertrust_azure_subscription_details" "subs" {
  connection_id = ciphertrust_azure_connection.connection.id
}

# Optionally pre-fetch vault details to avoid the Azure lookup on creation.
# Pass an entry from this map to vault_details on the resource below.
data "ciphertrust_azure_vault_details" "vaults" {
  connection_id   = ciphertrust_azure_connection.connection.id
  subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
}

resource "ciphertrust_azure_vault" "vault" {
  name            = "my-key-vault"
  connection_id   = ciphertrust_azure_connection.connection.id
  subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id

  # Optional: supply vault_details from ciphertrust_azure_vault_details to skip the
  # Azure lookup on creation. Immutable after creation.
  # vault_details = data.ciphertrust_azure_vault_details.vaults.vaults["my-key-vault"]

  # Optional: limit the number of allowed key backups for this vault.
  cloud_key_backup_limit = 10
}

# The cckm_vault_name computed attribute holds the "vault-name::subscription-id" string
# used as the name filter in ciphertrust_azure_vault_list.
data "ciphertrust_azure_vault_list" "registered" {
  filters = {
    name = ciphertrust_azure_vault.vault.cckm_vault_name
  }
}
