terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.1.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-aes-key-${lower(random_id.random.hex)}"
  kms_name        = "tf-aes-key-${lower(random_id.random.hex)}"
  key_name        = "tf-aes-key-${lower(random_id.random.hex)}"
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

# # Minimum input parameters for a symmetric key
# resource "ciphertrust_aws_key" "aes_min_params" {
#   kms_id = ciphertrust_aws_kms.kms.id
#   region = ciphertrust_aws_kms.kms.regions[0]
# }

# After creation, create a key rotation scheduler and attach it to the AES key via update
resource "ciphertrust_scheduler" "scheduled_rotation" {
  cckm_key_rotation_params = {
    cloud_name       = "aws"
    expiration       = "2d"
    aws_retain_alias = true
    rotate_material  = true
  }
  name      = "name"
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}

# Maximum input parameters for a symmetric key
resource "ciphertrust_aws_key" "aes_key_max_params" {
  # auto_rotate              = true  # update only
  enable_key                 = true
  kms_id                     = ciphertrust_aws_kms.kms.id
  region                     = ciphertrust_aws_kms.kms.regions[0]
  schedule_for_deletion_days = 10
  aws_param = {
    alias                              = [local.key_name]
    bypass_policy_lockout_safety_check = false
    customer_master_key_spec           = "SYMMETRIC_DEFAULT"
    description                        = "desc for aes_key_max_params"
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
  enable_rotation = {
    job_config_id = ciphertrust_scheduler.scheduled_rotation.id
    key_source = "local"
  }
}
