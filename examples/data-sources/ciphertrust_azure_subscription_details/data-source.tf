# Retrieve all Azure subscriptions visible to the given connection.
# This queries Azure directly, not the CipherTrust Manager database.
# Use ciphertrust_azure_subscription_list to query subscriptions already
# added to CipherTrust Manager.

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

# Output the Azure subscription ID of the first subscription found.
output "first_subscription_id" {
  value = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
}
