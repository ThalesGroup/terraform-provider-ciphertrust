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
  connection_name = "tf-azure-acls-${lower(random_id.random.hex)}"
  user_name       = "tf-azure-acls-user-${lower(random_id.random.hex)}"
  group_name      = "tf-azure-acls-group-${lower(random_id.random.hex)}"
  user_password   = "Secure-${upper(random_id.random.hex)}-1!"
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

# Add an existing Azure vault to CipherTrust Manager
resource "ciphertrust_azure_vault" "vault" {
  name            = var.azure_non_purgeable_vault
  connection_id   = ciphertrust_azure_connection.connection.id
  subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
}

# Create a CipherTrust Manager user
resource "ciphertrust_user" "user" {
  username = local.user_name
  password = local.user_password
}

# Create an ACL that gives the user access to the vault
resource "ciphertrust_azure_acl" "user_acl" {
  vault_id = ciphertrust_azure_vault.vault.id
  user_id  = ciphertrust_user.user.user_id
  actions  = ["view", "keycreate"]
}

# Create a CipherTrust Manager group
resource "ciphertrust_groups" "group" {
  name = local.group_name
}

# Create an ACL that gives the group access to the vault
resource "ciphertrust_azure_acl" "group_acl" {
  vault_id = ciphertrust_azure_vault.vault.id
  group    = ciphertrust_groups.group.name
  actions  = ["view", "keyupdate"]
}

# List the vault after creating the ACL resources
data "ciphertrust_azure_vault_list" "vault" {
  filters = {
    name = ciphertrust_azure_vault.vault.cckm_vault_name
  }
  depends_on = [ciphertrust_azure_acl.user_acl, ciphertrust_azure_acl.group_acl]
}
output "vault" {
  value = data.ciphertrust_azure_vault_list.vault
}
