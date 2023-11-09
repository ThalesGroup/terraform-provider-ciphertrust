terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.2-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "aws-connection-${lower(random_id.random.hex)}"
  kms_name        = "kms-${lower(random_id.random.hex)}"
  key_name        = "cm-aes-upload-${lower(random_id.random.hex)}"
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

# Create an AES CipherTrust key
resource "ciphertrust_cm_key" "cm_aes_key" {
  name      = local.key_name
  algorithm = "AES"
}
output "cm_aes_key" {
  value = ciphertrust_cm_key.cm_aes_key
}

# Upload the CipherTrust key AWS
resource "ciphertrust_aws_key" "aws_aes_key" {
  alias  = [local.key_name]
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  upload_key {
    source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
  }
}
output "aws_aes_key" {
  value = ciphertrust_aws_key.aws_aes_key
}
