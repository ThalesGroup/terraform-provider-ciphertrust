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
  connection_name         = "tf-sync-scheduler-${lower(random_id.random.hex)}"
  kms_name                = "tf-sync-scheduler-${lower(random_id.random.hex)}"
  sync_all_scheduler_name = "tf-sync-all-scheduler-${lower(random_id.random.hex)}"
  sync_kms_scheduler_name = "tf-sync-kms-scheduler-${lower(random_id.random.hex)}"
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

# Synchronization can also be scheduled for all KMS resources
resource "ciphertrust_scheduler" "sync_all" {
  cckm_synchronization_params {
    cloud_name      = "aws"
    synchronize_all = true
  }
  name      = local.sync_kms_scheduler_name
  operation = "cckm_synchronization"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}

# Schedule synchronization of specific KMSes
resource "ciphertrust_scheduler" "sync_kms" {
  cckm_synchronization_params {
    cloud_name = "aws"
    kms        = [ciphertrust_aws_kms.kms.id]
  }
  name      = local.sync_all_scheduler_name
  operation = "cckm_synchronization"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}
