terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.1.0"
    }
  }
}

provider "ciphertrust" {
  cloud_key_manager = {
    azure = {
      # The vault does not support purge, so a destroyed secret is only soft-deleted.
      purge_secrets_on_delete = false
      # Recover a soft-deleted secret of the same name instead of failing.
      recover_soft_deleted_secrets = true
    }
  }
}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-azure-secrets-${lower(random_id.random.hex)}"
  secret_name     = "tf-secret-${lower(random_id.random.hex)}"
}

# Define an Azure connection
resource "ciphertrust_azure_connection" "connection" {
  name          = local.connection_name
  client_id     = var.azure_client_id
  tenant_id     = var.azure_tenant_id
  client_secret = var.azure_client_secret
  products      = ["cckm"]
}

# Add an existing Azure vault to CipherTrust Manager
resource "ciphertrust_azure_vault" "vault" {
  name            = var.azure_non_purgeable_vault
  connection_id   = ciphertrust_azure_connection.connection.id
  subscription_id = var.azure_subscription_id
}

# Create a secret in the Azure vault.
resource "ciphertrust_azure_secret" "secret" {
  name     = local.secret_name
  vault_id = ciphertrust_azure_vault.vault.id
  azure_params = {
    value        = "my-secret-value"
    content_type = "password"
    tags = {
      source = "terraform-sample"
    }
  }
}

# Output the secret. The secret value is sensitive and is not read back from Azure.
output "secret" {
  value     = ciphertrust_azure_secret.secret
  sensitive = true
}