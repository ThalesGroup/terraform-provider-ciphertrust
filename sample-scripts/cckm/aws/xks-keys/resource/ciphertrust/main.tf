terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {}

# A custom key store can be deleted only after all XKS keys in it have been destroyed and it is disconnected.
# Keys can be scheduled for deletion in the minimum of 7 days.

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-xks-${lower(random_id.random.hex)}"
  kms_name        = "tf-xks-${lower(random_id.random.hex)}"
  key_name        = "tf-xks-${lower(random_id.random.hex)}"
  cks_name        = "tf-xks-${lower(random_id.random.hex)}"
  endpoint        = "https://endpoint.com"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = local.connection_name
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws-connection.id
}

# Create a kms
resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws-connection.id
  name           = local.kms_name
  regions        = [data.ciphertrust_aws_account_details.account_details.regions[0]]
}

# Create an AES CipherTrust Manager key
resource "ciphertrust_cm_key" "aes_key" {
  name                         = local.key_name
  algorithm                    = "AES"
  usage_mask                   = 60
  unexportable                 = true
  undeletable                  = true
  remove_from_state_on_destroy = true
}

resource "ciphertrust_aws_custom_keystore" "custom_keystore" {
  name                        = local.cks_name
  region                      = data.ciphertrust_aws_account_details.account_details.regions[0]
  kms                         = ciphertrust_aws_kms.kms.id
  linked_state                = true
  connect_disconnect_keystore = "CONNECT_KEYSTORE"
  local_hosted_params {
    blocked             = false
    health_check_key_id = ciphertrust_cm_key.aes_key.id
    max_credentials     = 8
    source_key_tier     = "local"
  }
  aws_param {
    xks_proxy_uri_endpoint = local.endpoint
    xks_proxy_connectivity = "PUBLIC_ENDPOINT"
    custom_key_store_type  = "EXTERNAL_KEY_STORE"
  }
}

# Create an XKS key with CipherTrust Manager as key source
resource "ciphertrust_aws_xks_key" "xks_key" {
  alias       = [local.key_name]
  description = "desc for xks_key"
  local_hosted_params {
    blocked             = false
    custom_key_store_id = ciphertrust_aws_custom_keystore.custom_keystore.id
    linked              = true
    source_key_id       = ciphertrust_cm_key.aes_key.id
    source_key_tier     = "local"
  }
}
