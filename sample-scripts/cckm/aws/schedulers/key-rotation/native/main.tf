terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.9.0-beta4"
    }
  }
}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name         = "tf-native-rotation-${lower(random_id.random.hex)}"
  kms_name                = "tf-native-rotation-${lower(random_id.random.hex)}"
  key_name                = "tf-native-rotation-${lower(random_id.random.hex)}"
  rotation_scheduler_name = "tf-native-rotation-${lower(random_id.random.hex)}"
}

resource "ciphertrust_aws_connection" "aws_connection" {
  name = local.connection_name
}

data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws_connection.id
}

resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = local.kms_name
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Create scheduled rotation job to run every Saturday at 9 am
resource "ciphertrust_scheduler" "rotation_job" {
  cckm_key_rotation_params {
    cloud_name = "aws"
  }
  name      = local.rotation_scheduler_name
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}

# Create an AES AWS key and schedule it for rotation, the new key will be sourced from AWS
resource "ciphertrust_aws_key" "aws_key" {
  alias = [local.key_name]
  enable_rotation {
    job_config_id = ciphertrust_scheduler.rotation_job.id
  }
  kms    = ciphertrust_aws_kms.kms.id
  origin = "AWS_KMS"
  region = ciphertrust_aws_kms.kms.regions[0]
}
