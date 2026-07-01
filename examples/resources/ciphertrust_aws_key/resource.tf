# Pre-requisites for AWS keys - AWS connection, AWS KMS
# Define an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = "aws-connection-name"
}
output "aws_connection_id" {
  value = ciphertrust_aws_connection.aws-connection.id
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws-connection.id
}

# Define a kms
resource "ciphertrust_aws_kms" "kms" {
  depends_on = [
    ciphertrust_aws_connection.aws-connection,
  ]
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws-connection.id
  name           = "kms-name"
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

resource "ciphertrust_scheduler" "scheduled_rotation" {
  cckm_key_rotation_params = {
    cloud_name       = "aws"
    expiration       = "2d"
    aws_retain_alias = true
  }
  name      = "scheduler-name"
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}

# Define a native AWS symmetric key
resource "ciphertrust_aws_key" "aws_key" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
}

# Define a native AWS RSA 2048 key with an alias and description
resource "ciphertrust_aws_key" "aws_rsa_key" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  aws_param = {
    alias                    = ["my-rsa-key"]
    customer_master_key_spec = "RSA_2048"
    description              = "RSA 2048 key"
    key_usage                = "ENCRYPT_DECRYPT"
  }
}

# Define a multi-region key
resource "ciphertrust_aws_key" "aws_multiregion_key" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  aws_param = {
    multi_region = true
  }
  enable_rotation = {
    disable_encrypt = false
    job_config_id   = ciphertrust_scheduler.scheduled_rotation.id
    key_source      = "ciphertrust"
  }
}

# Replicate the above key and make the replica the primary key
resource "ciphertrust_aws_key" "replicated_key" {
  region = ciphertrust_aws_kms.kms.regions[1]
  replicate_key = {
    key_id       = ciphertrust_aws_key.aws_multiregion_key.id
    make_primary = true
  }
}

# Define an AWS key and enable autorotation by AWS
resource "ciphertrust_aws_key" "auto_rotated_aws_key" {
  kms_id      = ciphertrust_aws_kms.kms.id
  region      = ciphertrust_aws_kms.kms.regions[0]
  auto_rotate = true
  aws_param = {
    auto_rotation_period_in_days = 128
  }
}
