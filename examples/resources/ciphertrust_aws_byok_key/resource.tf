# Pre-requisites for AWS BYOK keys - AWS connection, AWS KMS
# Define an AWS connection
resource "ciphertrust_aws_connection" "aws_connection" {
  name = "aws-connection-name"
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws_connection.id
}

# Define a KMS
resource "ciphertrust_aws_kms" "kms" {
  depends_on = [
    ciphertrust_aws_connection.aws_connection,
  ]
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = "kms-name"
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Define a CipherTrust Manager AES key to use as BYOK source material
resource "ciphertrust_cm_key" "byok_source" {
  name      = "byok-source-key"
  algorithm = "AES"
  size      = 256
}

# Minimal BYOK key - uploads CipherTrust Manager key material to a new AWS EXTERNAL key
resource "ciphertrust_aws_byok_key" "minimal" {
  kms_id                = ciphertrust_aws_kms.kms.id
  region                = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier = ciphertrust_cm_key.byok_source.id
  source_key_tier       = "local"
}

# BYOK key with optional attributes - alias, description, tags, and expiry
resource "ciphertrust_aws_byok_key" "with_options" {
  kms_id                    = ciphertrust_aws_kms.kms.id
  region                    = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier     = ciphertrust_cm_key.byok_source.id
  source_key_tier           = "local"
  enable_key                = true
  schedule_for_deletion_days = 14
  aws_param = {
    alias       = ["my-byok-key", "my-byok-key-alias-2"]
    description = "BYOK key with imported CipherTrust Manager material"
    tags = {
      Environment = "production"
      Owner       = "platform-team"
      CostCentre  = "cc-1234"
    }
    valid_to = "2030-01-01T00:00:00Z"
  }
}

# Multi-region BYOK primary key
resource "ciphertrust_aws_byok_key" "mr_primary" {
  kms_id                = ciphertrust_aws_kms.kms.id
  region                = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier = ciphertrust_cm_key.byok_source.id
  source_key_tier       = "local"
  aws_param = {
    alias       = ["my-mr-byok-key"]
    description = "Multi-region BYOK primary key"
    multi_region = true
    tags = {
      Environment = "production"
      KeyType     = "multi-region-primary"
    }
  }
}

# Replica of the multi-region BYOK primary key in a second region
# Key material is imported automatically from the primary key
resource "ciphertrust_aws_byok_key" "mr_replica" {
  region = ciphertrust_aws_kms.kms.regions[1]
  replicate_key = {
    key_id       = ciphertrust_aws_byok_key.mr_primary.id
    make_primary = false
  }
}

# Scheduler for BYOK key rotation
resource "ciphertrust_scheduler" "byok_rotation" {
  cckm_key_rotation_params = {
    cloud_name       = "aws"
    expiration       = "2d"
    aws_retain_alias = true
    rotate_material  = true
  }
  name      = "byok-rotation-scheduler"
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}

# BYOK key with a scheduled rotation job registered at creation
resource "ciphertrust_aws_byok_key" "with_rotation" {
  kms_id                = ciphertrust_aws_kms.kms.id
  region                = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier = ciphertrust_cm_key.byok_source.id
  source_key_tier       = "local"
  aws_param = {
    alias       = ["my-rotating-byok-key"]
    description = "BYOK key with scheduled rotation"
    tags = {
      Environment = "production"
      Rotation    = "scheduled"
    }
  }
  enable_rotation = {
    disable_encrypt = false
    job_config_id   = ciphertrust_scheduler.byok_rotation.id
    key_source      = "ciphertrust"
  }
}
