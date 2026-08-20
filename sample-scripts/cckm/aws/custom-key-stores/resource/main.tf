terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.1"
    }
  }
}

# A custom key store can be deleted only after all XKS keys in it have been destroyed and it is disconnected.
# Keys can be scheduled for deletion in the minimum of 7 days.

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  aws_connection_name = "tf-cks-${lower(random_id.random.hex)}"
  kms_name            = "tf-cks-${lower(random_id.random.hex)}"
  key_name            = "tf-cks-${lower(random_id.random.hex)}"
  cks_name            = "tf-cks-${lower(random_id.random.hex)}"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "connection" {
  name = local.aws_connection_name
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  connection_id = ciphertrust_aws_connection.connection.id
}

# Create a kms
resource "ciphertrust_aws_kms" "kms" {
  name          = local.kms_name
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.connection.id
  regions       = [data.ciphertrust_aws_account_details.account_details.regions[0]]
}

# Create an AES CipherTrust Manager key
resource "ciphertrust_cm_key" "cm_aes_key" {
  name                         = local.key_name
  algorithm                    = "AES"
  usage_mask                   = 60
  unexportable                 = true
  undeletable                  = true
  remove_from_state_on_destroy = true
}

resource "ciphertrust_aws_custom_keystore" "custom_keystore" {
  name   = local.cks_name
  region = data.ciphertrust_aws_account_details.account_details.regions[0]
  kms_id = ciphertrust_aws_kms.kms.id
  local_hosted_params = {
    health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
    max_credentials     = 4
    source_key_tier     = "local"
  }
}
