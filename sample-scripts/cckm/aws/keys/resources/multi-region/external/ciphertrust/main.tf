terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.0-pre3"
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
  connection_id = ciphertrust_aws_connection.connection.id
}

resource "ciphertrust_aws_kms" "kms" {
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.connection.id
  name          = local.kms_name
  regions       = data.ciphertrust_aws_account_details.account_details.regions
}

resource "ciphertrust_cm_key" "rsa" {
  name      = local.key_name
  algorithm = "RSA"
  key_size  = 2048
}

# Create a multi-region EXTERNAL RSA primary key and upload key material from CipherTrust Manager
resource "ciphertrust_aws_byok_key" "rsa" {
  kms_id                = ciphertrust_aws_kms.kms.id
  region                = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier = ciphertrust_cm_key.rsa.id
  source_key_tier       = "local"
  aws_param = {
    alias                    = [local.aws_key_alias]
    customer_master_key_spec = "RSA_2048"
    multi_region             = true
  }
}

# Replicate the primary key to a second region. Key material is imported automatically.
resource "ciphertrust_aws_byok_key" "replica" {
  region = ciphertrust_aws_kms.kms.regions[1]
  replicate_key = {
    key_id = ciphertrust_aws_byok_key.rsa.id
  }
}
