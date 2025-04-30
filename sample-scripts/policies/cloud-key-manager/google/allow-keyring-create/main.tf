terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.11.1"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  group_name      = "google-group-${lower(random_id.random.hex)}"
  policy_name     = "google-policy-${lower(random_id.random.hex)}"
  connection_name = "google-connection-${lower(random_id.random.hex)}"
  keyring_permissions = [
    "AddKeyRingsCCKM",
    "ReadGcpKeyRing",
    "GetKeyRingsCCKM",
  ]
  user_name     = "google-user-${lower(random_id.random.hex)}"
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

# Create a policy to allow a user to add GCP keyrings
resource "ciphertrust_policies" "policy" {
  name    = local.policy_name
  actions = concat(local.keyring_permissions)
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

# Create a GCP connection so the user can add a keyring
resource "ciphertrust_gcp_connection" "connection" {
  key_file = var.gcp_key_file
  name     = local.connection_name
}
output "gcp_connection_id" {
  value = ciphertrust_gcp_connection.connection.id
}
output "gcp_connection_name" {
  value = ciphertrust_gcp_connection.connection.name
}
