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

# Create a 2048 bit RSA AWS key
resource "ciphertrust_aws_key" "aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
}

# Upload an existing CipherTrust key to AWS
resource "ciphertrust_aws_key" "aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.cm_key.id
  }
}

# Upload an existing DSM key to AWS
resource "ciphertrust_aws_key" "aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
  upload_key {
    source_key_identifier = ciphertrust_dsm_key.dsm_key.id
    source_key_tier       = "dsm"
  }
}

# Create a new CipherTrust key and import its key material to a new AWS key
resource "ciphertrust_aws_key" "aws_key" {
  import_key_material {
    source_key_name = "cm-key-name"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
}

# Create a new DSM key and import its key material to a new AWS key
resource "ciphertrust_aws_key" "aws_key" {
  import_key_material {
    dsm_domain_id   = ciphertrust_dsm_domain.dsm_domain.id
    source_key_name = "dsm-key-name"
    source_key_tier = "dsm"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
}

# Create a multi-region key
resource "ciphertrust_aws_key" "aws_multiregion_key" {
  kms          = ciphertrust_aws_kms.kms.id
  multi_region = true
  region       = "aws-region"
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
resource "ciphertrust_aws_key" "replicated_key" {
  region = "alternative-aws-region"
  replicate_key {
    import_key_material = true
    key_id              = ciphertrust_aws_key.aws_external_multiregion_key.key_id
  }
}

# Schedule key rotation using a CipherTrust Manager as the key source
resource "ciphertrust_aws_key" "aws_multiregion_key" {
  enable_rotation {
    disable_encrypt = false
    job_config_id   = ciphertrust_scheduler.scheduled_rotation_job.id
    key_source      = "ciphertrust"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
}

# Schedule key rotation for a key using a DSM as the key source
resource "ciphertrust_aws_key" "aws_multiregion_key" {
  enable_rotation {
    dsm_domain_id = ciphertrust_dsm_domain.dsm_domain.id
    job_config_id = ciphertrust_scheduler.scheduled_rotation_job.id
    key_source    = "dsm"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
}

# Create am AWS key and enable autorotation by AWS
resource "ciphertrust_aws_key" "aws_key" {
  kms         = ciphertrust_aws_kms.kms.id
  region      = "aws-region"
  auto_rotate = true
}

