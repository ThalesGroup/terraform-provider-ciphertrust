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
  cckm_key_rotation_params {
    cloud_name       = "aws"
    expiration       = "2d"
    aws_retain_alias = true
  }
  name      = "scheduler-name"
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}

# Define a 2048 bit RSA AWS key
resource "ciphertrust_aws_key" "aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
}

# Define an AES CipherTrust key to upload to AWS
resource "ciphertrust_cm_key" "cm_key" {
  name      = "cm-key-name"
  algorithm = "aes"
}

# Upload an existing CipherTrust key to AWS
resource "ciphertrust_aws_key" "upload_aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  upload_key {
    source_key_identifier = ciphertrust_cm_key.cm_key.id
  }
}

# Define a new CipherTrust key and import its key material to a new AWS key
resource "ciphertrust_aws_key" "import_aws_key" {
  import_key_material {
    source_key_name = "key-name"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
}

# Define a multi-region key
resource "ciphertrust_aws_key" "aws_multiregion_key" {
  kms          = ciphertrust_aws_kms.kms.id
  multi_region = true
  region       = ciphertrust_aws_kms.kms.regions[0]
  enable_rotation {
    disable_encrypt = false
    job_config_id   = ciphertrust_scheduler.scheduled_rotation.id
    key_source      = "ciphertrust"
  }
}

# Replicate the above key and make the replica the primary key
resource "ciphertrust_aws_key" "replicated_key" {
  region = ciphertrust_aws_kms.kms.regions[1]
  replicate_key {
    key_id       = ciphertrust_aws_key.aws_multiregion_key.key_id
    make_primary = true
  }
}

# Define an AWS multi-region key and import its key material from a CipherTrust key
resource "ciphertrust_aws_key" "aws_external_multiregion_key" {
  import_key_material {
    source_key_name = "cm-key-name"
  }
  kms          = ciphertrust_aws_kms.kms.id
  multi_region = true
  region       = ciphertrust_aws_kms.kms.regions[0]
}

# Replicate the above key to another region and import the same key material to the replica
resource "ciphertrust_aws_key" "external_replicated_key" {
  region = ciphertrust_aws_kms.kms.regions[1]
  replicate_key {
    import_key_material = true
    key_id              = ciphertrust_aws_key.aws_external_multiregion_key.key_id
  }
}

# Define am AWS key and enable autorotation by AWS
resource "ciphertrust_aws_key" "auto_rotated_aws_key" {
  kms                          = ciphertrust_aws_kms.kms.id
  region                       = ciphertrust_aws_kms.kms.regions[0]
  auto_rotate                  = true
  auto_rotation_period_in_days = 128
}
