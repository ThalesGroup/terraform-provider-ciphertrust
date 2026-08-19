terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.0-pre3"
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
  connection_id = ciphertrust_aws_connection.connection.id
}

resource "ciphertrust_aws_kms" "kms" {
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.connection.id
  name          = local.kms_name
  regions       = data.ciphertrust_aws_account_details.account_details.regions
}

resource "ciphertrust_aws_key" "rsa" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  aws_param = {
    alias                    = [local.key_name]
    customer_master_key_spec = "RSA_2048"
    multi_region             = true
  }
}

resource "ciphertrust_aws_key" "replica" {
  region = ciphertrust_aws_kms.kms.regions[1]
  replicate_key = {
    key_id       = ciphertrust_aws_key.rsa.id
    make_primary = true
  }
  aws_param = {
    alias = [local.key_name]
  }
}
