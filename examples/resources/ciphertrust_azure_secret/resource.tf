# Pre-requisites for an Azure secret - Azure connection, Azure vault.
# This file shows the available options and need not be valid as a whole.

# Provider settings that affect Azure secrets. All are optional.
provider "ciphertrust" {
  cloud_key_manager = {
    azure = {
      # On destroy, purge a secret after it is soft-deleted, if purge is
      # supported by the vault. Default is true. If false, the secret is only
      # soft-deleted.
      purge_secrets_on_delete = true

      # If creating a secret fails because the name belongs to a soft-deleted
      # secret, recover that secret instead. Default is false.
      recover_soft_deleted_secrets = false
    }
  }
}

# Define an Azure connection
resource "ciphertrust_azure_connection" "connection" {
  name          = "azure-connection"
  client_id     = "your-client-id"
  tenant_id     = "your-tenant-id"
  client_secret = "your-client-secret"
  products      = ["cckm"]
}

# Get the subscriptions available to the connection
data "ciphertrust_azure_subscription_details" "subs" {
  connection_id = ciphertrust_azure_connection.connection.id
}

# Add an Azure vault to CipherTrust Manager
resource "ciphertrust_azure_vault" "vault" {
  name            = "my-key-vault"
  connection_id   = ciphertrust_azure_connection.connection.id
  subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
}

# Create a secret in the vault with the minimum options.
# name and azure_params.value are required. The value is not read back after
# the secret is created.
resource "ciphertrust_azure_secret" "minimal" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = "minimal-secret"
  azure_params = {
    value = "my-secret-value"
  }
}

# Create a secret in the vault with all the available options.
# Only content_type, tags and attributes can be updated after the secret is
# created. Everything else is immutable.
resource "ciphertrust_azure_secret" "secret" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = "my-secret"
  azure_params = {
    value        = "my-secret-value"
    content_type = "password"
    # Optional. Set tags = {} to remove all tags.
    tags = {
      environment = "test"
    }
    # Optional
    attributes = {
      enabled = true
      # RFC3339 format, UTC. expiration_date must be later than activation_date.
      # A date cannot be cleared once it is set.
      activation_date = "2026-07-03T14:24:00Z"
      expiration_date = "2030-07-03T14:24:00Z"
    }
  }
}

# Restore a purged secret into a vault from its CipherTrust Manager backup.
# secret_id is the CipherTrust Manager ID of the purged secret. It is no longer
# in Terraform state, so it is not a reference to another resource. vault_id can
# be any vault. name and azure_params cannot be set.
resource "ciphertrust_azure_secret" "restored" {
  vault_id = ciphertrust_azure_vault.vault.id
  restore_secret = {
    secret_id = "purged-secret-id"
  }
}