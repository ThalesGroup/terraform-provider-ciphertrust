terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.10-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "connection-${lower(random_id.random.hex)}"
  kms_name        = "kms-${lower(random_id.random.hex)}"
  bucket_name     = "aws-bucket-${lower(random_id.random.hex)}"
  key_name        = "aws-bucket-${lower(random_id.random.hex)}"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = local.connection_name
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws-connection.id
}

# Create a kms
resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws-connection.id
  name           = local.kms_name
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Create a symmetric key
resource "ciphertrust_aws_key" "key" {
  alias = [local.key_name]
  kms   = ciphertrust_aws_kms.kms.id
  import_key_material {
    source_key_name = local.key_name
    source_key_tier = "local"
  }
  region = ciphertrust_aws_kms.kms.regions[0]
  origin = "EXTERNAL"
}

# Create an AWS S3 bucket using the key for encryption
resource "aws_s3_bucket" "test_bucket" {
  bucket = local.bucket_name
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = ciphertrust_aws_key.key.arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
}
