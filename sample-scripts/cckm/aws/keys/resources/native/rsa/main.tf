terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-rsa-key-${lower(random_id.random.hex)}"
  kms_name        = "tf-rsa-key-${lower(random_id.random.hex)}"
  key_name        = "tf-rsa-key-${lower(random_id.random.hex)}"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = local.connection_name
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
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws-connection.id
  name           = local.kms_name
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Minimum input parameters for an RSA key
resource "ciphertrust_aws_key" "rsa_min_params" {
  customer_master_key_spec = "RSA_3072"
  kms                      = ciphertrust_aws_kms.kms.id
  region                   = ciphertrust_aws_kms.kms.regions[0]
}

# Maximum input parameters for an RSA key
resource "ciphertrust_aws_key" "rsa_max_params" {
  alias                              = [local.key_name]
  bypass_policy_lockout_safety_check = true
  description                        = "desc for rsa_key_max_params"
  enable_key                         = false
  kms                                = ciphertrust_aws_kms.kms.id
  customer_master_key_spec           = "RSA_4096"
  key_usage                          = "SIGN_VERIFY"
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
