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
  connection_name = "tf-mr-native-${lower(random_id.random.hex)}"
  kms_name        = "tf-mr-native-${lower(random_id.random.hex)}"
  key_name        = "tf-mr-native-${lower(random_id.random.hex)}"
}

provider "ciphertrust" {}

resource "ciphertrust_aws_connection" "connection" {
  name = local.connection_name
}

data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.connection.id
}

resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.connection.id
  name           = local.kms_name
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

resource "ciphertrust_aws_key" "rsa" {
  alias                    = [local.key_name]
  customer_master_key_spec = "RSA_2048"
  kms                      = ciphertrust_aws_kms.kms.id
  multi_region             = true
  region                   = ciphertrust_aws_kms.kms.regions[0]
  primary_region           = ciphertrust_aws_kms.kms.regions[1]
}

resource "ciphertrust_aws_key" "replica" {
  alias  = [local.key_name]
  origin = "AWS_KMS"
  region = ciphertrust_aws_kms.kms.regions[1]
  replicate_key {
    key_id       = ciphertrust_aws_key.rsa.key_id
    make_primary = true
  }
}
