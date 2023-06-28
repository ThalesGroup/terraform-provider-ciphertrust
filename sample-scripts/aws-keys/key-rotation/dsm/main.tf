terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.0-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  aws_connection_name = "aws-connection-${lower(random_id.random.hex)}"
  dsm_connection_name = "dsm-connection-${lower(random_id.random.hex)}"
  kms_name            = "kms-${lower(random_id.random.hex)}"
  key_name            = "dsm-rotation-${lower(random_id.random.hex)}"
  rotation_job_name   = "aws-dsm-${lower(random_id.random.hex)}"
}

resource "ciphertrust_aws_connection" "aws_connection" {
  name = local.aws_connection_name
}

data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws_connection.id
}

resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = local.aws_connection_name
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Create a dsm connection
resource "ciphertrust_dsm_connection" "dsm_connection" {
  name = local.dsm_connection_name
  nodes {
    hostname    = var.dsm_ip
    certificate = var.dsm_certificate
  }
  password = var.dsm_password
  username = var.dsm_username
}

# Add a dsm domain
resource "ciphertrust_dsm_domain" "dsm_domain" {
  dsm_connection = ciphertrust_dsm_connection.dsm_connection.id
  domain_id      = var.dsm_domain
}

# Create scheduled rotation job to run at 11 pm every day
resource "ciphertrust_scheduler" "rotation_job" {
  cckm_key_rotation_params {
    cloud_name = "aws"
  }
  name      = local.rotation_job_name
  operation = "cckm_key_rotation"
  run_at    = "0 23 * * *"
  run_on    = "any"
}
output "rotation_job" {
  value = ciphertrust_scheduler.rotation_job
}

# Create an AES AWS key and schedule it for rotation
# The new key will be sourced from the dsm
resource "ciphertrust_aws_key" "aws_key" {
  alias = [local.key_name]
  enable_rotation {
    disable_encrypt = true
    dsm_domain_id   = ciphertrust_dsm_domain.dsm_domain.id
    job_config_id   = ciphertrust_scheduler.rotation_job.id
    key_source      = "dsm"
  }
  kms    = ciphertrust_aws_kms.kms.id
  origin = "AWS_KMS"
  region = ciphertrust_aws_kms.kms.regions[0]
}
output "key" {
  value = ciphertrust_aws_key.aws_key
}
