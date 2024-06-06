terraform {
  required_providers {
    ciphertrust = {
      source = "thales.com/terraform/ciphertrust"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "aws-connection-${lower(random_id.random.hex)}"
  kms_name_one    = "aws-kms-${lower(random_id.random.hex)}-one"
  kms_name_two    = "aws-kms-${lower(random_id.random.hex)}-two"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "connection" {
  name = local.connection_name
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.connection.id
}

# Create a KMS resource using the first regions in the AWS account
resource "ciphertrust_aws_kms" "kms_one" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.connection.id
  name           = local.kms_name_one
  regions = [
    data.ciphertrust_aws_account_details.account_details.regions[0],
    data.ciphertrust_aws_account_details.account_details.regions[1],
    data.ciphertrust_aws_account_details.account_details.regions[3],
  ]
}

# Create another KMS resource using the next regions in the AWS account
resource "ciphertrust_aws_kms" "kms_two" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.connection.id
  name           = local.kms_name_two
  regions = [
    data.ciphertrust_aws_account_details.account_details.regions[4],
    data.ciphertrust_aws_account_details.account_details.regions[5],
  ]
}

# Create a datasource
data "ciphertrust_aws_kms" "no_params" {
  # Depends is required so the kms resources will be created first
  depends_on = [ciphertrust_aws_kms.kms_one, ciphertrust_aws_kms.kms_two]
}

# Create a key using datasource above
resource "ciphertrust_aws_key" "aws_key_by_no_params" {
  customer_master_key_spec = "RSA_2048"
  kms                      = data.ciphertrust_aws_kms.no_params.kms[0].kms_id
  key_usage                = "ENCRYPT_DECRYPT"
  region                   = data.ciphertrust_aws_kms.no_params.kms[0].regions[0]
}

# Input is connection name
data "ciphertrust_aws_kms" "by_connection" {
  # Depends is required so kms resources will be created first
  depends_on     = [ciphertrust_aws_kms.kms_one, ciphertrust_aws_kms.kms_two]
  aws_connection = ciphertrust_aws_connection.connection.name
}

# Create a key using datasource above
resource "ciphertrust_aws_key" "aws_key_by_connection" {
  customer_master_key_spec = "RSA_2048"
  kms                      = data.ciphertrust_aws_kms.by_connection.kms[1].kms_id
  key_usage                = "ENCRYPT_DECRYPT"
  region                   = data.ciphertrust_aws_kms.by_connection.kms[1].regions[0]
}

# Input is kms name
data "ciphertrust_aws_kms" "by_kms_name" {
  kms_name   = ciphertrust_aws_kms.kms_one.name
}

# Create a key using datasource above
resource "ciphertrust_aws_key" "aws_key_by_kms_name" {
  customer_master_key_spec = "RSA_2048"
  kms                      = data.ciphertrust_aws_kms.by_kms_name.kms[0].kms_id
  key_usage                = "ENCRYPT_DECRYPT"
  region                   = data.ciphertrust_aws_kms.by_kms_name.kms[0].regions[1]
}
