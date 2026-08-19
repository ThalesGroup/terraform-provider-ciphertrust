# Pre-requisites for AWS BYOK keys - AWS connection, AWS KMS
# Define an AWS connection
resource "ciphertrust_aws_connection" "aws_connection" {
  name = "name"
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  connection_id = ciphertrust_aws_connection.aws_connection.id
}

# Define a KMS
resource "ciphertrust_aws_kms" "kms" {
  depends_on = [
    ciphertrust_aws_connection.aws_connection,
  ]
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.aws_connection.id
  name          = "name"
  regions       = data.ciphertrust_aws_account_details.account_details.regions
}

# Create a key rotation scheduler for key rotation
resource "ciphertrust_scheduler" "scheduled_rotation" {
  cckm_key_rotation_params = {
    cloud_name       = "aws"
    expiration       = "2d"
    aws_retain_alias = true
    rotate_material  = true
  }
  name      = "name"
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}

# Define a CipherTrust Manager AES key to use as BYOK source material
resource "ciphertrust_cm_key" "local_aes" {
  name      = "name"
  algorithm = "AES"
  size      = 256
}

# BYOK key with optional attributes - alias, description, tags, and material expiry
resource "ciphertrust_aws_byok_key" "byok_key" {
  kms_id                     = ciphertrust_aws_kms.kms.id
  region                     = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier      = ciphertrust_cm_key.local_aes.id
  source_key_tier            = "local"
  schedule_for_deletion_days = 14
  aws_param = {
    alias                    = ["alias"]
    customer_master_key_spec = "SYMMETRIC_DEFAULT"
    description              = "description"
    tags = {
      Environment = "environment"
    }
    valid_to = "2030-01-01T00:00:00Z"
  }
}

# After creation, update aliases, tags, description and add a scheduler by updating the resource:
resource "ciphertrust_aws_byok_key" "byok_key" {
  kms_id                     = ciphertrust_aws_kms.kms.id
  region                     = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier      = ciphertrust_cm_key.local_aes.id
  source_key_tier            = "local"
  schedule_for_deletion_days = 14
  aws_param = {
    alias                    = ["alias", "alias-2"]
    customer_master_key_spec = "SYMMETRIC_DEFAULT"
    description              = "updated-description"
    tags = {
      Environment = "environment"
      Product     = "line"
    }
    valid_to = "2030-01-01T00:00:00Z"
  }
  enable_rotation = {
    disable_encrypt = false
    job_config_id   = ciphertrust_scheduler.scheduled_rotation.id
    key_source      = "ciphertrust"
  }
}

# Multi-region BYOK primary key
resource "ciphertrust_aws_byok_key" "byok_key_mr_primary" {
  kms_id                = ciphertrust_aws_kms.kms.id
  region                = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier = ciphertrust_cm_key.local_aes.id
  source_key_tier       = "local"
  aws_param = {
    alias        = ["alias"]
    description  = "description"
    multi_region = true
  }
}

# Replica of the above multi-region BYOK key in a second region
# Key material is imported automatically from the primary key
resource "ciphertrust_aws_byok_key" "byok_key_mr_replica" {
  region = ciphertrust_aws_kms.kms.regions[1]
  replicate_key = {
    key_id = ciphertrust_aws_byok_key.byok_key_mr_primary.id
  }
}
