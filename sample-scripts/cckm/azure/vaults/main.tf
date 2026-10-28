terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.1.0"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-azure-vaults-${lower(random_id.random.hex)}"
}

# Define an Azure connection
resource "ciphertrust_azure_connection" "connection" {
  name          = local.connection_name
  client_id     = var.azure_client_id
  tenant_id     = var.azure_tenant_id
  client_secret = var.azure_client_secret
  products      = ["cckm"]
}

# Get the subscriptions available to the connection
data "ciphertrust_azure_subscription_details" "subs" {
  connection_id = ciphertrust_azure_connection.connection.id
}

# List the Key Vaults in the subscription directly from Azure. The result is a map keyed by vault name.
data "ciphertrust_azure_vault_details" "vaults" {
  connection_id   = ciphertrust_azure_connection.connection.id
  subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
}
output "azure_vault_names" {
  value = keys(data.ciphertrust_azure_vault_details.vaults.vaults)
}

# Add the vault to CipherTrust Manager. Passing vault_details from the data source above
# skips the Azure lookup on creation.
resource "ciphertrust_azure_vault" "vault" {
  name            = var.azure_non_purgeable_vault
  connection_id   = ciphertrust_azure_connection.connection.id
  subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
  vault_details   = data.ciphertrust_azure_vault_details.vaults.vaults[var.azure_non_purgeable_vault]
}

# List the vault in CipherTrust Manager. cckm_vault_name is in "vault-name::subscription-id" format.
data "ciphertrust_azure_vault_list" "added" {
  filters = {
    name = ciphertrust_azure_vault.vault.cckm_vault_name
  }
}
output "added_vault" {
  value = data.ciphertrust_azure_vault_list.added
}
