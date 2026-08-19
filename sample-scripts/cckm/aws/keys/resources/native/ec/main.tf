terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-ec-key-${lower(random_id.random.hex)}"
  kms_name        = "tf-ec-key-${lower(random_id.random.hex)}"
  key_name        = "tf-ec-key-${lower(random_id.random.hex)}"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = local.connection_name
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  connection_id = ciphertrust_aws_connection.aws-connection.id
}

# Create a kms
resource "ciphertrust_aws_kms" "kms" {
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.aws-connection.id
  name          = local.kms_name
  regions       = data.ciphertrust_aws_account_details.account_details.regions
}

# Minimum input parameters for an EC key
resource "ciphertrust_aws_key" "ec_min_params" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  aws_param = {
    customer_master_key_spec = "ECC_SECG_P256K1"
  }
}

# Maximum input parameters for an EC key
resource "ciphertrust_aws_key" "ec_max_params" {
  enable_key                 = true
  kms_id                     = ciphertrust_aws_kms.kms.id
  region                     = ciphertrust_aws_kms.kms.regions[0]
  schedule_for_deletion_days = 8
  aws_param = {
    alias                              = [local.key_name]
    bypass_policy_lockout_safety_check = true
    customer_master_key_spec           = "ECC_NIST_P384"
    description                        = "desc for ec_max_params"
    key_usage                          = "SIGN_VERIFY"
    tags = {
      TagKey = "TagValue"
    }
  }
  key_policy = {
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
  }
}
