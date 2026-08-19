terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {}

# Note: ciphertrust_aws_key_material manages key material for EXTERNAL symmetric keys.
# For EXTERNAL asymmetric or HMAC keys use ciphertrust_aws_byok_key with source_key_identifier.

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name  = "tf-import-${lower(random_id.random.hex)}"
  kms_name         = "tf-import-${lower(random_id.random.hex)}"
  aes_key_name     = "tf-import-aes-${lower(random_id.random.hex)}"
  material_v1_name = "tf-import-aes-material-v1-${lower(random_id.random.hex)}"
  material_v2_name = "tf-import-aes-material-v2-${lower(random_id.random.hex)}"
}

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
  regions       = [data.ciphertrust_aws_account_details.account_details.regions[0]]
}

# Create an EXTERNAL AES key in PendingImport state (no source_key_identifier)
resource "ciphertrust_aws_byok_key" "aes" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  aws_param = {
    alias                    = [local.aes_key_name]
    customer_master_key_spec = "SYMMETRIC_DEFAULT"
  }
}

# CipherTrust Manager AES keys used as key material versions
resource "ciphertrust_cm_key" "material_v1" {
  name      = local.material_v1_name
  algorithm = "AES"
  size      = 256
}

resource "ciphertrust_cm_key" "material_v2" {
  name      = local.material_v2_name
  algorithm = "AES"
  size      = 256
}

# Import key material into the EXTERNAL key.
# The key transitions from PendingImport to Enabled once material_v1 is applied.
# To rotate key material, add material_v2 - the provider imports it and calls
# rotate-material so material_v2 becomes CURRENT and material_v1 moves to PREVIOUS.
resource "ciphertrust_aws_key_material" "km" {
  aws_key_id = ciphertrust_aws_byok_key.aes.key_id
  kms_id     = ciphertrust_aws_kms.kms.id

  key_material {
    source_key_identifier = ciphertrust_cm_key.material_v1.id
    source_key_tier       = "local"
  }

  # Uncomment to rotate to a new key material version:
  # key_material {
  #   source_key_identifier = ciphertrust_cm_key.material_v2.id
  #   source_key_tier       = "local"
  # }
}
