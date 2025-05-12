terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.9.0-beta4"
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
  aws_connection = ciphertrust_aws_connection.connection.id
}

# Create a kms
resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.connection.id
  name           = local.kms_name
  regions = [
    data.ciphertrust_aws_account_details.account_details.regions[0],
    data.ciphertrust_aws_account_details.account_details.regions[1],
  ]
}

# Create a multi-region AWS key
resource "ciphertrust_aws_key" "aws_key" {
  alias                    = [local.key_name]
  customer_master_key_spec = "RSA_2048"
  kms                      = ciphertrust_aws_kms.kms.id
  key_usage                = "ENCRYPT_DECRYPT"
  multi_region             = true
  region                   = data.ciphertrust_aws_account_details.account_details.regions[0]
}

# Replicate key to another region
resource "ciphertrust_aws_key" "replicated_key" {
  alias  = [local.key_name]
  origin = "AWS_KMS"
  region = data.ciphertrust_aws_account_details.account_details.regions[1]
  replicate_key {
    key_id = ciphertrust_aws_key.aws_key.key_id
  }
}

# Read the key using the Terraform resource ID
data "ciphertrust_aws_key" "using_terraform_id" {
  id = ciphertrust_aws_key.aws_key.id
}
output "using_id" {
  value = data.ciphertrust_aws_key.using_terraform_id.id
}

# Read the key using the CipherTrust Manager key resource ID
data "ciphertrust_aws_key" "using_key_id" {
  key_id = ciphertrust_aws_key.aws_key.key_id
}
output "using_key_id" {
  value = data.ciphertrust_aws_key.using_key_id.id
}

# Read the key using the alias and region
data "ciphertrust_aws_key" "using_alias_and_region" {
  alias  = [local.key_name]
  region = ciphertrust_aws_key.aws_key.region
}
output "using_alias_and_region" {
  value = data.ciphertrust_aws_key.using_alias_and_region.id
}

# Read the replicated key using the alias and region
data "ciphertrust_aws_key" "replicated_using_alias" {
  alias  = [local.key_name]
  region = ciphertrust_aws_key.replicated_key.region
}
output "replicated_using_alias_and_region_1" {
  value = data.ciphertrust_aws_key.replicated_using_alias.id
}

# Read the key using the ARN
data "ciphertrust_aws_key" "using_arn" {
  arn = ciphertrust_aws_key.aws_key.arn
}
output "using_arn" {
  value = data.ciphertrust_aws_key.using_arn.id
}

# Read the key using the AWS key ID and region
data "ciphertrust_aws_key" "using_aws_key_id" {
  aws_key_id = ciphertrust_aws_key.aws_key.aws_key_id
  region     = ciphertrust_aws_key.aws_key.region
}
output "using_aws_key_id_and_region" {
  value = data.ciphertrust_aws_key.using_aws_key_id.id
}

# Read the replicated key using the AWS key ID and region
data "ciphertrust_aws_key" "replicated_using_aws_key_id" {
  aws_key_id = ciphertrust_aws_key.aws_key.aws_key_id
  region     = ciphertrust_aws_key.replicated_key.region
}
output "replicated_using_aws_key_id_and_region" {
  value = data.ciphertrust_aws_key.replicated_using_aws_key_id.id
}
