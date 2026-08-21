terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-key-ds-${lower(random_id.random.hex)}"
  kms_name        = "tf-key-ds-${lower(random_id.random.hex)}"
  key_name        = "tf-key-ds-${lower(random_id.random.hex)}"
}

# Data source input can be literal strings. These examples use attributes of a terraform key.

# Create an AWS connection
resource "ciphertrust_aws_connection" "connection" {
  name = local.connection_name
}

# Read the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  connection_id = ciphertrust_aws_connection.connection.id
}

# Create a kms
resource "ciphertrust_aws_kms" "kms" {
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.connection.id
  name          = local.kms_name
  regions = [
    data.ciphertrust_aws_account_details.account_details.regions[0],
    data.ciphertrust_aws_account_details.account_details.regions[1],
  ]
}

# Create a multi-region AWS key
resource "ciphertrust_aws_key" "aws_key" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = data.ciphertrust_aws_account_details.account_details.regions[0]
  aws_param = {
    alias                    = [local.key_name]
    customer_master_key_spec = "RSA_2048"
    key_usage                = "ENCRYPT_DECRYPT"
    multi_region             = true
  }
}

# Replicate key to another region
resource "ciphertrust_aws_key" "replicated_key" {
  region = data.ciphertrust_aws_account_details.account_details.regions[1]
  replicate_key = {
    key_id = ciphertrust_aws_key.aws_key.id
  }
  aws_param = {
    alias = [local.key_name]
  }
}

# Read the key using the CipherTrust Manager resource ID filter
data "ciphertrust_aws_keys_list" "using_id" {
  filters = { "id" = ciphertrust_aws_key.aws_key.id }
}
output "using_id" {
  value = data.ciphertrust_aws_keys_list.using_id.keys[0].key_id
}

# Read the key using the alias filter
data "ciphertrust_aws_keys_list" "using_alias" {
  filters = {
    "alias"  = local.key_name
    "region" = ciphertrust_aws_key.aws_key.region
  }
}
output "using_alias_and_region" {
  value = data.ciphertrust_aws_keys_list.using_alias.keys[0].key_id
}

# Read the replicated key using alias and region
data "ciphertrust_aws_keys_list" "replicated_using_alias" {
  filters = {
    "alias"  = local.key_name
    "region" = ciphertrust_aws_key.replicated_key.region
  }
}
output "replicated_using_alias_and_region" {
  value = data.ciphertrust_aws_keys_list.replicated_using_alias.keys[0].key_id
}

# Read the key using the ARN filter
data "ciphertrust_aws_keys_list" "using_arn" {
  filters = { "arn" = ciphertrust_aws_key.aws_key.aws_param.arn }
}
output "using_arn" {
  value = data.ciphertrust_aws_keys_list.using_arn.keys[0].key_id
}

# Read the key using the AWS key ID and region filters
data "ciphertrust_aws_keys_list" "using_aws_key_id" {
  filters = {
    "keyid"  = ciphertrust_aws_key.aws_key.aws_param.key_id
    "region" = ciphertrust_aws_key.aws_key.region
  }
}
output "using_aws_key_id_and_region" {
  value = data.ciphertrust_aws_keys_list.using_aws_key_id.keys[0].key_id
}

# Read the replicated key using the AWS key ID and region filters
data "ciphertrust_aws_keys_list" "replicated_using_aws_key_id" {
  filters = {
    "keyid"  = ciphertrust_aws_key.aws_key.aws_param.key_id
    "region" = ciphertrust_aws_key.replicated_key.region
  }
}
output "replicated_using_aws_key_id_and_region" {
  value = data.ciphertrust_aws_keys_list.replicated_using_aws_key_id.keys[0].key_id
}
