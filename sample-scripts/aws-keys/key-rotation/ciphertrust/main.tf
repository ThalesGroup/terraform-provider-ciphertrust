terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.3-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name   = "aws-connection-${lower(random_id.random.hex)}"
  kms_name          = "kms-${lower(random_id.random.hex)}"
  key_name          = "cm-rotation-${lower(random_id.random.hex)}"
  rotation_job_name = "aws-cm-${lower(random_id.random.hex)}"
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
  name      = local.rotation_job_name
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}
output "rotation_job" {
  value = ciphertrust_scheduler.rotation_job
}

# Create an AES AWS key and schedule it for rotation
# The new key will be sourced from CipherTrust
resource "ciphertrust_aws_key" "aws_key" {
  alias = [local.key_name]
  enable_rotation {
    job_config_id = ciphertrust_scheduler.rotation_job.id
    key_source    = "ciphertrust"
  }
  kms    = ciphertrust_aws_kms.kms.id
  origin = "AWS_KMS"
  region = ciphertrust_aws_kms.kms.regions[0]
}
output "key" {
  value = ciphertrust_aws_key.aws_key
}
