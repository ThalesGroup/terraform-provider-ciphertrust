terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-hmac-key-${lower(random_id.random.hex)}"
  kms_name        = "tf-hmac-key-${lower(random_id.random.hex)}"
  key_name        = "tf-hmac-key-${lower(random_id.random.hex)}"
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

# Minimum input parameters for a HMAC key
resource "ciphertrust_aws_key" "hmac_min_params" {
  kms                      = ciphertrust_aws_kms.kms.id
  customer_master_key_spec = "HMAC_384"
  region                   = ciphertrust_aws_kms.kms.regions[0]
}

# Maximum input parameters for a HMAC key
resource "ciphertrust_aws_key" "hmac_max_params" {
  alias                              = [local.key_name]
  bypass_policy_lockout_safety_check = true
  description                        = "desc for hmac_max_params"
  enable_key                         = true
  kms                                = ciphertrust_aws_kms.kms.id
  customer_master_key_spec           = "HMAC_256"
  key_usage                          = "GENERATE_VERIFY_MAC"
  tags = {
    TagKey = "TagValue"
  }
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Id" : "kms-tf-1",
      "Statement" : [{
        "Sid" : "Enable IAM User Permissions 1",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "*"
        },
        "Action" : "kms:*",
        "Resource" : "*"
      }]
    }
  )
  region                     = ciphertrust_aws_kms.kms.regions[0]
  schedule_for_deletion_days = 8
}
