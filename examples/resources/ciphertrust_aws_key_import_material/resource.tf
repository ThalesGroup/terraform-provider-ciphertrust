# ciphertrust_aws_key_import_material has been superseded by ciphertrust_aws_key_material.
# Use ciphertrust_aws_byok_key to create an EXTERNAL key and ciphertrust_aws_key_material
# to import and manage key material versions.

# Pre-requisites
resource "ciphertrust_aws_connection" "aws_connection" {
  name = "aws-connection-name"
}

data "ciphertrust_aws_account_details" "account_details" {
  connection_id = ciphertrust_aws_connection.aws_connection.id
}

resource "ciphertrust_aws_kms" "kms" {
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.aws_connection.id
  name          = "kms-name"
  regions       = [data.ciphertrust_aws_account_details.account_details.regions[0]]
}

# Create an EXTERNAL symmetric key in PendingImport state
resource "ciphertrust_aws_byok_key" "ext_key" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  aws_param = {
    alias = ["my-external-key"]
  }
}

# CipherTrust Manager AES key to use as key material
resource "ciphertrust_cm_key" "new_key_material" {
  name      = "new-material"
  algorithm = "AES"
  size      = 256
}

# Import key material - the key transitions from PendingImport to Enabled
resource "ciphertrust_aws_key_material" "km" {
  aws_key_id = ciphertrust_aws_byok_key.ext_key.key_id
  kms_id     = ciphertrust_aws_kms.kms.id

  key_material {
    source_key_identifier = ciphertrust_cm_key.new_key_material.id
    source_key_tier       = "local"
  }
}
