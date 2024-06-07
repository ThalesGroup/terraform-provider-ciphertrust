terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.5-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  aws_connection_name = "aws-connection-${lower(random_id.random.hex)}"
  dsm_connection_name = "dsm-connection-${lower(random_id.random.hex)}"
  kms_name            = "kms-${lower(random_id.random.hex)}"
  key_name            = "dsm-aes-upload-${lower(random_id.random.hex)}"
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

# Create a dsm connection
resource "ciphertrust_dsm_connection" "dsm_connection" {
  name = local.dsm_connection_name
  nodes {
    hostname    = var.dsm_ip
    certificate = var.dsm_certificate
  }
  password = var.dsm_password
  username = var.dsm_username
}

# Add a dsm domain
resource "ciphertrust_dsm_domain" "dsm_domain" {
  dsm_connection = ciphertrust_dsm_connection.dsm_connection.id
  domain_id      = var.dsm_domain
}

# Create a dsm AES key to upload to AWS
resource "ciphertrust_dsm_key" "dsm_aes_key" {
  name            = local.key_name
  algorithm       = "AES256"
  domain          = ciphertrust_dsm_domain.dsm_domain.id
  encryption_mode = "CBC"
  extractable     = true
  object_type     = "symmetric"
}

# Upload the dsm key to AWS
resource "ciphertrust_aws_key" "aws_aes_key" {
  alias  = [local.key_name]
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  upload_key {
    source_key_identifier = ciphertrust_dsm_key.dsm_aes_key.id
    source_key_tier       = "dsm"
  }
}
output "aws_aes_key" {
  value = ciphertrust_aws_key.aws_aes_key
}
