terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.11.2"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  luna_hsm_connection_name = "luna-hsm-connection-${lower(random_id.random.hex)}"
  aws_connection_name = "aws-connection-${lower(random_id.random.hex)}"
  kms_name        = "kms-${lower(random_id.random.hex)}"
  template_with_users_and_roles = "template-with-users-and-roles-${lower(random_id.random.hex)}"
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
  regions        = ["us-west-1"]
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

# Create Luna HSM server, Luna Connection, Luna Symmetric key and virtual key for Luna as key source

# Create a Luna HSM server
resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = var.hsm_hostname
  hsm_certificate = var.hsm_certificate
}

# Create a Luna HSM connection
# is_ha_enabled must be true for more than one partition
resource "ciphertrust_hsm_connection" "hsm_connection" {
  depends_on = [
    ciphertrust_hsm_server.hsm_server,
  ]
  hostname  = var.hsm_hostname
  server_id = ciphertrust_hsm_server.hsm_server.id
  name      = local.luna_hsm_connection_name
  partitions {
    partition_label = var.hsm_partition_label
    serial_number   = var.hsm_partition_serial_number
  }
  partition_password = var.hsm_partition_password
  is_ha_enabled      = false
}
output "hsm_connection_id" {
  value = ciphertrust_hsm_connection.hsm_connection.id
}

# Add a Luna HSM partition to connection
resource "ciphertrust_hsm_partition" "hsm_partition" {
  depends_on = [
    ciphertrust_hsm_connection.hsm_connection,
  ]
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
}
output "hsm_partition" {
  value = ciphertrust_hsm_partition.hsm_partition
}

# Create an Symmetric AES-256 Luna HSM key for creating EXTERNAL_KEY_STORE with Luna as key source
resource "ciphertrust_hsm_key" "hsm_aes_key" {
  depends_on = [
    ciphertrust_hsm_partition.hsm_partition,
  ]
  attributes = ["CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP", "CKA_UNWRAP"]
  label        = "key-name-${lower(random_id.random.hex)}"
  mechanism    = "CKM_AES_KEY_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
  key_size     = 256
  hyok_key     = true
}

output "hsm_aes_key" {
  value = ciphertrust_hsm_key.hsm_aes_key
}

# Create linked external custom keystore with luna as key source; with xks proxy connectivity as PUBLIC_ENDPOINT
resource "ciphertrust_aws_custom_keystore" "linked_xks_custom_keystore_for_luna_as_source" {
  depends_on = [
    ciphertrust_aws_kms.kms,
    ciphertrust_hsm_partition.hsm_partition,
    ciphertrust_hsm_key.hsm_aes_key,
  ]
  name = var.cks_name
  region = var.cks_region
  kms    = ciphertrust_aws_kms.kms.name
  linked_state = var.cks_linked
  connect_disconnect_keystore = var.cks_aws_cks_connect_disconnect_state
  local_hosted_params {
    blocked = var.cks_blocked
    health_check_key_id = ciphertrust_hsm_key.hsm_aes_key.id
    max_credentials = var.cks_max_credentials_count
    source_key_tier = var.cks_aws_xks_source_key_tier
    partition_id = ciphertrust_hsm_partition.hsm_partition.id
  }
  aws_param {
    xks_proxy_uri_endpoint = var.cks_aws_xks_uri_endpoint
    xks_proxy_connectivity = var.cks_aws_xks_proxy_connectivity
    custom_key_store_type = var.cks_aws_xks_custom_keystore_type
  }
}

output "linked_xks_custom_keystore_for_luna_as_source" {
  value = ciphertrust_aws_custom_keystore.linked_xks_custom_keystore_for_luna_as_source
}

# Set blocked = true to block data plane operations on all keys in above linked keystore
# Set connect_disconnect_keystore = CONNECT_KEYSTORE before creating linked AWS XKS (HYOK) key

# Create a virtual key from above luna key
resource "ciphertrust_virtual_key" "virtual_key_from_luna_key" {
  depends_on = [
    ciphertrust_hsm_key.hsm_aes_key,
  ]
  deletable = var.virtual_key_deletable
  source_key_id = ciphertrust_hsm_key.hsm_aes_key.id
  source_key_tier = var.cks_aws_xks_source_key_tier
}
output "virtual_key_from_luna_key" {
  value = ciphertrust_virtual_key.virtual_key_from_luna_key
}

# Create an linked XKS key with luna as key source in linked key store create above
resource "ciphertrust_aws_xks_key" "xks_linked_key_with_luna_as_source_1" {
  depends_on = [
    ciphertrust_aws_custom_keystore.linked_xks_custom_keystore_for_luna_as_source,
    ciphertrust_aws_policy_template.template_with_users_and_roles,
    ciphertrust_virtual_key.virtual_key_from_luna_key,
  ]

  local_hosted_params {
    blocked = var.xks_key_blocked
    custom_key_store_id = ciphertrust_aws_custom_keystore.linked_xks_custom_keystore_for_luna_as_source.id
    linked = var.xks_key_linked
    source_key_id = ciphertrust_virtual_key.virtual_key_from_luna_key.id
    source_key_tier = var.cks_aws_xks_source_key_tier
  }
  description = "desc for xks_linked_key_with_luna_as_source_1"
  alias = ["a1_luna_linked_key_12"]
  tags = {
    Tagkey1 = "TagValue1"
    Tagkey2 = "TagValue2"
  }
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
  }
}

output "xks_linked_key_with_luna_as_source_1" {
  value = ciphertrust_aws_xks_key.xks_linked_key_with_luna_as_source_1
}

# Set blocked = true to prevent data plane operations using this key
# Modify description, tag, alias, enable/disable key, etc, using respective fields
# Set deletable = true for ciphertrust_virtual_key resource before deleting the virtual key
# External key store can be deleted only after deleting HYOK (XKS) keys in it.
# For linked HYOK (XKS) key, key can be scheduled to be deleted between 7-30 days.
