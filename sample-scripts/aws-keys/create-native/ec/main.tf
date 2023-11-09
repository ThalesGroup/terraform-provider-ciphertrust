terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.2-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "aws-connection-${lower(random_id.random.hex)}"
  kms_name        = "kms-${lower(random_id.random.hex)}"
  min_key_name    = "ec-min-params-${lower(random_id.random.hex)}"
  max_key_name    = "ec-max-params-${lower(random_id.random.hex)}"
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
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Minimum input parameters for an EC key
resource "ciphertrust_aws_key" "ec_key_min_params" {
  # Alias is optional
  alias                    = [local.min_key_name]
  kms                      = ciphertrust_aws_kms.kms.id
  customer_master_key_spec = "ECC_SECG_P256K1"
  region                   = ciphertrust_aws_kms.kms.regions[0]
}
output "ec_key_min_params" {
  value = ciphertrust_aws_key.ec_key_min_params
}

# Maximum input parameters for an EC key
resource "ciphertrust_aws_key" "ec_key_max_params" {
  alias                              = [local.max_key_name]
  bypass_policy_lockout_safety_check = true
  enable_key                         = true
  kms                                = ciphertrust_aws_kms.kms.id
  customer_master_key_spec           = "ECC_NIST_P384"
  key_usage                          = "SIGN_VERIFY"
  tags = {
    TagKey = "TagValue"
  }
  #key_policy {
  #}
  region                     = ciphertrust_aws_kms.kms.regions[0]
  schedule_for_deletion_days = 14
}
output "ec_key_max_params" {
  value = ciphertrust_aws_key.ec_key_max_params
}
