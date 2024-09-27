terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.6-beta"
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
  key_name            = "hsm-aes-upload-${lower(random_id.random.hex)}"
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

# Create a HSM AES key to upload to AWS
resource "ciphertrust_hsm_key" "hsm_aes_key" {
  attributes   = ["CKA_ENCRYPT", "CKA_DECRYPT"]
  label        = local.key_name
  mechanism    = "CKM_AES_KEY_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
  key_size     = 256
}
output "hsm_aes_key" {
  value = ciphertrust_hsm_key.hsm_aes_key
}

# Upload the dsm key to AWS
resource "ciphertrust_aws_key" "aws_aes_key" {
  alias  = [local.key_name]
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  upload_key {
    source_key_identifier = ciphertrust_hsm_key.hsm_aes_key.id
    source_key_tier       = "hsm-luna"
  }
}
output "aws_aes_key" {
  value = ciphertrust_aws_key.aws_aes_key
}
