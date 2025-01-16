terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.7-beta"
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
  key_name            = "dsm-import-${lower(random_id.random.hex)}"
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
  name           = local.kms_name
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

# Import the key material of the dsm key to the AWS key
resource "ciphertrust_aws_key" "aws_key" {
  alias = [local.key_name]
  import_key_material {
    dsm_domain_id   = ciphertrust_dsm_domain.dsm_domain.id
    source_key_name = local.key_name
    source_key_tier = "dsm"
  }
  kms    = ciphertrust_aws_kms.kms.id
  origin = "EXTERNAL"
  region = ciphertrust_aws_kms.kms.regions[0]
}
output "key" {
  value = ciphertrust_aws_key.aws_key
}
