# Indirectly this resource is dependent on a ciphertrust_aws_connection resource
resource "ciphertrust_aws_connection" "aws_connection" {
  name = "connection-name"
}

# This resource is dependent on a ciphertrust_aws_kms resource
resource "ciphertrust_aws_kms" "kms" {
  account_id     = "aws-account-id"
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = "kms-name"
  regions        = ["aws-region"]
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

# Create a 2048 bit RSA AWS key
resource "ciphertrust_aws_key" "aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
}

# Create an AES CipherTrust key to upload to AWS
resource "ciphertrust_cm_key" "cm_key" {
  name      = "cm-key-name"
  algorithm = "aes"
}

# Upload an existing CipherTrust key to AWS
resource "ciphertrust_aws_key" "upload_aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.cm_key.id
  }
}

# Create a new CipherTrust key and import its key material to a new AWS key
resource "ciphertrust_aws_key" "import_aws_key" {
  import_key_material {
    source_key_name = "key-name"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
}

# Create a multi-region key
resource "ciphertrust_aws_key" "aws_multiregion_key" {
  kms          = ciphertrust_aws_kms.kms.id
  multi_region = true
  region       = "aws-region"
  enable_rotation {
    disable_encrypt = false
    job_config_id   = ciphertrust_scheduler.scheduled_rotation.id
    key_source      = "ciphertrust"
  }
}

# Replicate the above key and make the replica the primary key
resource "ciphertrust_aws_key" "replicated_key" {
  region = "alternative-aws-region"
  replicate_key {
    key_id       = ciphertrust_aws_key.aws_multiregion_key.key_id
    make_primary = true
  }
}

# Create an AWS multi-region key and import its key material from a CipherTrust key
resource "ciphertrust_aws_key" "aws_external_multiregion_key" {
  import_key_material {
    source_key_name = "cm-key-name"
  }
  kms          = ciphertrust_aws_kms.kms.id
  multi_region = true
  region       = "aws-region"
}

# Replicate the above key to another region and import the same key material to the replica
resource "ciphertrust_aws_key" "external_replicated_key" {
  region = "alternative-aws-region"
  replicate_key {
    import_key_material = true
    key_id              = ciphertrust_aws_key.aws_external_multiregion_key.key_id
  }
}

# Create am AWS key and enable autorotation by AWS
resource "ciphertrust_aws_key" "auto_rotated_aws_key" {
  kms         = ciphertrust_aws_kms.kms.id
  region      = ciphertrust_aws_kms.kms.regions[0]
  auto_rotate = true
  auto_rotation_period_in_days = 128
}
