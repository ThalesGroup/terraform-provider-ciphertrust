terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.0-pre3"
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
  aws_connection_name = "tf-cks-ds-${lower(random_id.random.hex)}"
  kms_name            = "tf-cks-ds-${lower(random_id.random.hex)}"
  key_name            = "tf-cks-ds-${lower(random_id.random.hex)}"
  cks_name            = "tf-cks-ds-${lower(random_id.random.hex)}"
  rotation_job_name   = "tf-cks-ds-${lower(random_id.random.hex)}"
  endpoint            = "https://endpoint.com"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "connection" {
  name = local.aws_connection_name
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.connection.id
}

# Create a kms
resource "ciphertrust_aws_kms" "kms" {
  name           = local.kms_name
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.connection.id
  regions        = [data.ciphertrust_aws_account_details.account_details.regions[0]]
}

# Create an AES CipherTrust Manager key
resource "ciphertrust_cm_key" "cm_aes_key" {
  name                         = local.key_name
  algorithm                    = "AES"
  usage_mask                   = 60
  unexportable                 = true
  undeletable                  = "true"
  remove_from_state_on_destroy = true
}

resource "ciphertrust_scheduler" "rotation" {
  end_date = "2027-03-07T14:00:00Z"
  cckm_xks_credential_rotation_params = {
    cloud_name = "aws"
  }
  name       = local.rotation_job_name
  operation  = "cckm_xks_credential_rotation"
  run_at     = "0 9 * * fri"
  run_on     = "any"
  start_date = "2025-03-07T14:00:00Z"
}

resource "ciphertrust_aws_custom_keystore" "custom_keystore" {
  name                        = local.cks_name
  region                      = data.ciphertrust_aws_account_details.account_details.regions[0]
  kms                         = ciphertrust_aws_kms.kms.id
  linked_state                = true
  connect_disconnect_keystore = "CONNECT_KEYSTORE"
  local_hosted_params {
    blocked             = false
    health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
    max_credentials     = 8
    source_key_tier     = "local"
  }
  aws_param {
    xks_proxy_uri_endpoint = local.endpoint
    xks_proxy_connectivity = "PUBLIC_ENDPOINT"
    custom_key_store_type  = "EXTERNAL_KEY_STORE"
  }
  enable_credential_rotation {
    job_config_id = ciphertrust_scheduler.rotation.id
  }
}

data "ciphertrust_aws_custom_keystore" "custom_keystore" {
  id = ciphertrust_aws_custom_keystore.custom_keystore.id
}
output "custom_keystore" {
  value = data.ciphertrust_aws_custom_keystore.custom_keystore
}
