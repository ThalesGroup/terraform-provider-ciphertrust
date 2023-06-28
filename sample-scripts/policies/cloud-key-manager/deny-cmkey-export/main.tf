terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.0-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  group_name    = "group-${lower(random_id.random.hex)}"
  policy_name   = "policy-${lower(random_id.random.hex)}"
  user_name     = "user-${lower(random_id.random.hex)}"
  user_password = "password"
}

resource "ciphertrust_user" "user" {
  username = local.user_name
  password = local.user_password
}
output "user_name" {
  value = ciphertrust_user.user.username
}

# Create a custom group, adding user
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

# Create a policy to deny export privileges of the CipherTrust key
resource "ciphertrust_policies" "policy" {
  name    = local.policy_name
  actions = ["ExportKey"]
  allow   = true
  effect  = "deny"
}
output "policy_id" {
  value = ciphertrust_policies.policy.id
}
output "policy_name" {
  value = ciphertrust_policies.policy.name
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
