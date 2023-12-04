terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.4-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "azure-connection-${lower(random_id.random.hex)}"
  group_name      = "azure-group-${lower(random_id.random.hex)}"
  policy_name     = "azure-policy-${lower(random_id.random.hex)}"
  vault_permissions = [
    "AddVaultCCKM",
    "GetAzurevaultCCKM",
    "ReadAzureVault",
    "UpdateVaultCCKM",
  ]
  user_name     = "azure-user-${lower(random_id.random.hex)}"
  user_password = "password"
}

# Create a CipherTrust user
resource "ciphertrust_user" "user" {
  username = local.user_name
  password = local.user_password
}
output "user_name" {
  value = ciphertrust_user.user.username
}

# Create a custom group and add user
resource "ciphertrust_groups" "custom_group" {
  name = local.group_name
  user_ids = [
    ciphertrust_user.user.id,
  ]
}
output "group_name" {
  value = ciphertrust_groups.custom_group.name
}

# Add user to CCKM Users group
resource "ciphertrust_groups" "CCKM_Users_Group" {
  name = "CCKM Users"
  user_ids = [
    ciphertrust_user.user.id,
  ]
}

# Add user to Key Users group
resource "ciphertrust_groups" "Key_Users_Group" {
  name = "Key Users"
  user_ids = [
    ciphertrust_user.user.id,
  ]
}

# Create a policy to allow a user to add an Azure key vault
resource "ciphertrust_policies" "policy" {
  name    = local.policy_name
  actions = concat(local.vault_permissions)
  allow   = true
  effect  = "allow"
}
output "policy_id" {
  value = ciphertrust_policies.policy.id
}
output "policy_name" {
  value = ciphertrust_policies.policy.name
}
output "policy" {
  value = ciphertrust_policies.policy
}

# Attach the policy to the custom group
resource "ciphertrust_policy_attachments" "attachment" {
  policy = ciphertrust_policies.policy.id
  principal_selector = jsonencode({
    groups = [ciphertrust_groups.custom_group.name]
  })
}
output "policy_attachment_id" {
  value = ciphertrust_policy_attachments.attachment.id
}

# Create an Azure connection so the user can add a vault
resource "ciphertrust_azure_connection" "connection" {
  name = local.connection_name
}
output "connection_id" {
  value = ciphertrust_azure_connection.connection.id
}
output "connection_name" {
  value = ciphertrust_azure_connection.connection.name
}
