terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.10-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  aws_connection_name = "aws-connection-${lower(random_id.random.hex)}"
  kms_name        = "kms-${lower(random_id.random.hex)}"
  min_key_name    = "aes-min-params-${lower(random_id.random.hex)}"
  cks_name = "cks-${lower(random_id.random.hex)}"
  template_with_users_and_roles = "template-with-users-and-roles-${lower(random_id.random.hex)}"
#  template_with_users_and_roles = "template-with-users-and-roles-test"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = local.aws_connection_name
  access_key_id     = var.access_key_id
  secret_access_key = var.secret_access_key
}
output "aws_connection_id" {
  value = ciphertrust_aws_connection.aws-connection.id
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws-connection.id
}

# Create a kms
resource "ciphertrust_aws_kms" "kms" {
  depends_on = [
    ciphertrust_aws_connection.aws-connection,
  ]
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws-connection.id
  name           = local.kms_name
#  regions        = data.ciphertrust_aws_account_details.account_details.regions
  regions        = [var.cks_region]
}

# Create a policy template using key users and roles
resource "ciphertrust_aws_policy_template" "template_with_users_and_roles" {
  name             = local.template_with_users_and_roles
  kms              = ciphertrust_aws_kms.kms.id
  key_admins       = [var.admin]
  key_admins_roles = [var.admin_role]
  key_users        = [var.user]
  key_users_roles  = [var.user_role]
}
output "template_with_users_and_roles" {
  value = ciphertrust_aws_policy_template.template_with_users_and_roles
}

# Create an AES CipherTrust key
resource "ciphertrust_cm_key" "cm_aes_key" {
  name      = local.min_key_name
  algorithm = "AES"
  usage_mask = 60
  unexportable = true
  undeletable = var.cm_key_undeletable
}
output "cm_aes_key" {
  value = ciphertrust_cm_key.cm_aes_key
}

# Create unlinked external custom keystore
resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore_for_cm_as_source" {
  depends_on = [
    ciphertrust_aws_kms.kms,
    ciphertrust_cm_key.cm_aes_key,
  ]
  name = "unlinked-xks-demo-1-for-cm-as-source"
  region = var.cks_region
  kms    = ciphertrust_aws_kms.kms.name
  linked_state = var.cks_linked
  connect_disconnect_keystore = var.cks_aws_cks_connect_disconnect_state
  local_hosted_params {
    blocked = var.cks_blocked
    health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
    max_credentials = var.cks_max_credentials_count
    source_key_tier = var.cks_aws_xks_source_key_tier
  }
  aws_param {
    xks_proxy_uri_endpoint = var.cks_aws_xks_uri_endpoint
    xks_proxy_connectivity = var.cks_aws_xks_proxy_connectivity
    custom_key_store_type = var.cks_aws_xks_custom_keystore_type
  }
}

output "unlinked_xks_custom_keystore_for_cm_as_source" {
  value = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source
}

data "ciphertrust_aws_custom_keystore" "data_unlinked_xks_custom_keystore_data" {
  depends_on = [
    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source,
  ]
  id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source.id
}
output "data_unlinked_xks_custom_keystore_data" {
  value = data.ciphertrust_aws_custom_keystore.data_unlinked_xks_custom_keystore_data
}

# Set connect_disconnect_keystore = CONNECT_KEYSTORE to connect above linked keystore
# Set blocked = true to block data plane operations in above linked keystore

# Create an XKS key with cm as key source
resource "ciphertrust_aws_xks_key" "xks_unlinked_key_with_cm_as_source_2" {
  depends_on = [
    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source,
    ciphertrust_cm_key.cm_aes_key,
    ciphertrust_aws_policy_template.template_with_users_and_roles,
  ]

  local_hosted_params {
    blocked = var.xks_key_blocked
    custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source.id
    linked = var.xks_key_linked
    source_key_id = ciphertrust_cm_key.cm_aes_key.id
    source_key_tier = var.cks_aws_xks_source_key_tier
  }
  description = "desc for xks_unlinked_key_with_cm_as_source_2"
  alias = ["a52_luna_unlinked_key_1"]
#  tags = {
#    Tagkey1 = "TagValue1"
#    Tagkey2 = "TagValue2"
#  }
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
  }
}

output "xks_unlinked_key_with_cm_as_source_2" {
  value = ciphertrust_aws_xks_key.xks_unlinked_key_with_cm_as_source_2
}

data "ciphertrust_aws_xks_key" "aws_key_data_source" {
  depends_on = [
    ciphertrust_aws_xks_key.xks_unlinked_key_with_cm_as_source_2,
  ]
  arn = ciphertrust_aws_xks_key.xks_unlinked_key_with_cm_as_source_2.arn
#  arn = "arn:aws:kms:us-west-1:556782317223:key/8209471b-20bd-4751-a7c2-8d0f3c21ee18"
}
output "data_source_aws_key_native_params" {
  value = data.ciphertrust_aws_xks_key.aws_key_data_source
}

# Set blocked = true to block above key from use in data plane operations