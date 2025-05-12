terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.9.0-beta4"
    }
  }
}

resource "random_id" "key_name" {
  byte_length = 8
}

locals {
  aws_key_alias   = "tf-mr-ct-${lower(random_id.key_name.hex)}"
  connection_name = "tf-mr-ct-${lower(random_id.key_name.hex)}"
  kms_name        = "tf-mr-ct-${lower(random_id.key_name.hex)}"
  key_name        = "tf-mr-ct-${lower(random_id.key_name.hex)}"
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

resource "ciphertrust_cm_key" "rsa" {
  name      = local.key_name
  algorithm = "RSA"
  key_size  = 2048
}

resource "ciphertrust_aws_key" "rsa" {
  alias                    = [local.aws_key_alias]
  customer_master_key_spec = "RSA_2048"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.rsa.id
  }
  kms          = ciphertrust_aws_kms.kms.id
  multi_region = true
  origin       = "EXTERNAL"
  region       = ciphertrust_aws_kms.kms.regions[0]
}

resource "ciphertrust_aws_key" "replica" {
  alias = [local.aws_key_alias]
  replicate_key {
    import_key_material = true
    key_id              = ciphertrust_aws_key.rsa.key_id
    make_primary        = true
  }
  origin = "EXTERNAL"
  region = ciphertrust_aws_kms.kms.regions[1]
}
