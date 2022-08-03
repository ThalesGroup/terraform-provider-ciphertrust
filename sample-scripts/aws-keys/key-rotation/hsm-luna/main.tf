terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.9.0-beta5"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  aws_connection_name = "aws-connection-${lower(random_id.random.hex)}"
  hsm_connection_name = "hsm-connection-${lower(random_id.random.hex)}"
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

# Create a hsm network server
resource "ciphertrust_hsm_server" "hsm_server" {
  description     = "Description of the HSM network server"
  hostname        = var.hsm_hostname
  hsm_certificate = var.hsm_certificate
  meta            = { key = "value" }
}

# Add create a hsm connection
resource "ciphertrust_hsm_connection" "hsm_connection" {
  hostname  = var.hsm_hostname
  server_id = ciphertrust_hsm_server.hsm_server.id
  name      = local.hsm_connection_name
  partitions {
    partition_label = var.hsm_partition_label
    serial_number   = var.hsm_partition_serial_number
  }
  partition_password = var.hsm_partition_password
}

# Add a partition to connection
resource "ciphertrust_hsm_partition" "hsm_partition" {
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
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
    disable_encrypt  = true
    hsm_partition_id = ciphertrust_hsm_partition.hsm_partition.id
    job_config_id    = ciphertrust_scheduler.rotation_job.id
    key_source       = "hsm-luna"
  }
  kms    = ciphertrust_aws_kms.kms.id
  origin = "AWS_KMS"
  region = ciphertrust_aws_kms.kms.regions[0]
}
output "key" {
  value = ciphertrust_aws_key.aws_key
}
