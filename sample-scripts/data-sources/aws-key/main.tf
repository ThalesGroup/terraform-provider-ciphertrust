terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.9.0-beta10"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "aws-connection-${lower(random_id.random.hex)}"
  kms_name        = "aws-kms-${lower(random_id.random.hex)}"
  key_name        = "aws-key-data-source-${lower(random_id.random.hex)}"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "connection" {
  name = local.connection_name
}

# Get the AWS account details
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
output "aws_key" {
  value = ciphertrust_aws_key.aws_key.id
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
output "replicated_key" {
  value = ciphertrust_aws_key.replicated_key.id
}

# Get the key using the Terraform resource ID
data "ciphertrust_aws_key" "key_from_terraform_id" {
  id = ciphertrust_aws_key.aws_key.id
}
output "key_from_id" {
  value = data.ciphertrust_aws_key.key_from_terraform_id.id
}

# Get the key using the CipherTrust key ID
data "ciphertrust_aws_key" "key_from_key_id" {
  key_id = ciphertrust_aws_key.aws_key.key_id
}
output "key_from_key_id" {
  value = data.ciphertrust_aws_key.key_from_key_id.id
}

# Get the key using the alias and region
data "ciphertrust_aws_key" "key_from_alias_and_region" {
  alias  = [local.key_name]
  region = ciphertrust_aws_key.aws_key.region
}
output "key_from_alias_and_region" {
  value = data.ciphertrust_aws_key.key_from_alias_and_region.id
}

# Get the replicated key using the alias and region
data "ciphertrust_aws_key" "replicated_key_from_alias" {
  alias  = [local.key_name]
  region = ciphertrust_aws_key.replicated_key.region
}
output "replicated_key_from_alias_and_region_1" {
  value = data.ciphertrust_aws_key.replicated_key_from_alias.id
}

# Get the key using the ARN
data "ciphertrust_aws_key" "key_from_arn" {
  arn = ciphertrust_aws_key.aws_key.arn
}
output "key_from_arn" {
  value = data.ciphertrust_aws_key.key_from_arn.id
}

# Get the key using the AWS key ID and region
data "ciphertrust_aws_key" "key_from_aws_key_id" {
  aws_key_id = ciphertrust_aws_key.aws_key.aws_key_id
  region     = ciphertrust_aws_key.aws_key.region
}
output "key_from_aws_key_id_and_region_0" {
  value = data.ciphertrust_aws_key.key_from_aws_key_id.id
}

# Get the replicated key using the AWS key ID and region
data "ciphertrust_aws_key" "replicated_key_from_aws_key_id" {
  aws_key_id = ciphertrust_aws_key.aws_key.aws_key_id
  region     = ciphertrust_aws_key.replicated_key.region
}
output "replicated_key_from_aws_key_id_and_region" {
  value = data.ciphertrust_aws_key.replicated_key_from_aws_key_id.id
}

# Get the key using all the possible parameters
data "ciphertrust_aws_key" "key_from_all_params" {
  alias      = [local.key_name]
  arn        = ciphertrust_aws_key.aws_key.arn
  aws_key_id = ciphertrust_aws_key.aws_key.aws_key_id
  id         = ciphertrust_aws_key.aws_key.id
  key_id     = ciphertrust_aws_key.aws_key.key_id
  region     = ciphertrust_aws_kms.kms.regions[0]
}
output "key_from_all_params" {
  value = data.ciphertrust_aws_key.key_from_all_params.id
}

# Get the replicated key using all the possible parameters
data "ciphertrust_aws_key" "replicated_key_from_all_params" {
  alias      = [local.key_name]
  arn        = ciphertrust_aws_key.replicated_key.arn
  aws_key_id = ciphertrust_aws_key.replicated_key.aws_key_id
  id         = ciphertrust_aws_key.replicated_key.id
  key_id     = ciphertrust_aws_key.replicated_key.key_id
  region     = ciphertrust_aws_kms.kms.regions[1]
}
output "replicated_key_from_all_params" {
  value = data.ciphertrust_aws_key.replicated_key_from_all_params.id
}
