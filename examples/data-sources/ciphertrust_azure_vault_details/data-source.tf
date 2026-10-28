# Retrieve Azure Key Vault details for a subscription directly from Azure.
# Useful for discovering vaults before adding them to CipherTrust Manager.
# The result is a map keyed by vault name - pass an entry directly to the
# vault_details attribute of ciphertrust_azure_vault to skip the Azure lookup
# on creation.

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

# List all Key Vaults in the subscription.
data "ciphertrust_azure_vault_details" "vaults" {
  connection_id   = ciphertrust_azure_connection.connection.id
  subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
}

# List Managed HSM vaults in the same subscription.
data "ciphertrust_azure_vault_details" "hsm_vaults" {
  connection_id   = ciphertrust_azure_connection.connection.id
  subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
  managed_hsms    = true
}

# Output the names of all discovered Key Vaults.
output "vault_names" {
  value = keys(data.ciphertrust_azure_vault_details.vaults.vaults)
}
