# Pre-requisites for AWS keys - AWS connection, AWS KMS
# Define an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = "name"
}
output "aws_connection_id" {
  value = ciphertrust_aws_connection.aws-connection.id
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  connection_id = ciphertrust_aws_connection.aws-connection.id
}

# Define a kms
resource "ciphertrust_aws_kms" "kms" {
  depends_on = [
    ciphertrust_aws_connection.aws-connection,
  ]
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.aws-connection.id
  name          = "name"
  regions       = data.ciphertrust_aws_account_details.account_details.regions
}

# Define a native AWS symmetric key
resource "ciphertrust_aws_key" "symm_key" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  aws_param = {
    alias                    = ["alias"]
    customer_master_key_spec = "SYMMETRIC_DEFAULT"
  }
}

# After creation, enable autorotation by updating the resource
resource "ciphertrust_aws_key" "symm_key" {
  kms_id      = ciphertrust_aws_kms.kms.id
  region      = ciphertrust_aws_kms.kms.regions[0]
  auto_rotate = true
  aws_param = {
    alias                        = ["alias"]
    customer_master_key_spec     = "SYMMETRIC_DEFAULT"
    auto_rotation_period_in_days = 128
  }
}

# Define a native AWS RSA 2048 key with an alias and description
resource "ciphertrust_aws_key" "rsa_key" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  aws_param = {
    alias                    = ["alias"]
    customer_master_key_spec = "RSA_2048"
    description              = "description"
    key_usage                = "ENCRYPT_DECRYPT"
  }
}

# After creation, create a key rotation scheduler and attach it to the RSA key via update
resource "ciphertrust_scheduler" "scheduled_rotation" {
  cckm_key_rotation_params = {
    cloud_name       = "aws"
    expiration       = "2d"
    aws_retain_alias = true
  }
  name      = "name"
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}

resource "ciphertrust_aws_key" "rsa_key" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  aws_param = {
    alias                    = ["alias"]
    customer_master_key_spec = "RSA_2048"
    description              = "description"
    key_usage                = "ENCRYPT_DECRYPT"
  }
  enable_rotation = {
    disable_encrypt = false
    job_config_id   = ciphertrust_scheduler.scheduled_rotation.id
    key_source      = "local"
  }
}

# Define a multi-region key
resource "ciphertrust_aws_key" "aws_multiregion_key" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  aws_param = {
    alias                    = ["alias"]
    customer_master_key_spec = "RSA_2048"
    description              = "description"
    key_usage                = "ENCRYPT_DECRYPT"
    multi_region             = true
  }
}

# Replicate the above key
resource "ciphertrust_aws_key" "replicated_key" {
  region = ciphertrust_aws_kms.kms.regions[1]
  replicate_key = {
    key_id = ciphertrust_aws_key.aws_multiregion_key.id
  }
  aws_param = {
    alias       = ["alias"]
    description = "description"
    tags = {
      tagKey = "tagValue"
    }
  }
}
