# Basic create key usage

resource "ciphertrust_aws_key" "aws_key" {
  alias                      = ["key_name"]
  kms                        = ciphertrust_aws_kms.kms.id
  region                     = "us-east-1"
}

# Upload a CipherTrust CM key to AWS

resource "ciphertrust_aws_key" "aws_key" {
  alias  = ["key_name"]
  kms    = ciphertrust_aws_kms.kms.id
  region = "us-east-1"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.cm_key.id
  }
}

# Import key material from a CipherTrust CM key

resource "ciphertrust_aws_key" "aws_key" {
  alias = ["key_name"]
  import_key_material {
    source_key_name = "cm_key_name"
  }
  kms    = ciphertrust_aws_kms.kms.id
  origin = "EXTERNAL"
  region = "us-east-1"
}

# Schedule key rotation using a DSM as the key source

resource "ciphertrust_aws_key" "aws_multiregion_key" {
  alias = ["alias_1", "alias_2"]
  enable_rotation {
    disable_encrypt = true
    dsm_domain_id   = ciphertrust_dsm_domain.dsm_domain.id
    job_config_id   = ciphertrust_scheduler.rotation_job.id
    key_source      = "dsm"
  }
  kms    = ciphertrust_aws_kms.kms.id
  origin = "AWS_KMS"
  region = "us-east-1"
}

# Create an multi-region key and replicates it to another region
# This example makes the replica the primary key following replication

resource "ciphertrust_aws_key" "aws_key" {
  alias        = ["multi-region-key"]
  kms          = ciphertrust_aws_kms.kms.id
  multi_region = true
  region       = "us-east-1"
}

resource "ciphertrust_aws_key" "replicated_key" {
  alias = ["replicated-key"]
  origin                             = "AWS_KMS"
  region                             = "us-north-1"
  replicate_key {
    key_id = ciphertrust_aws_key.aws_multiregion_key.key_id
    make_primary = true
  }
}

# Create an external multi-region key and replicates it to another region

resource "ciphertrust_aws_key" "aws_key" {
  alias = ["alias"]
  import_key_material {
    source_key_name = "cm_key_name"
  }
  kms          = ciphertrust_aws_kms.kms.id
  multi_region = true
  origin       = "EXTERNAL"
  region       = "us-east-1"
}

resource "ciphertrust_aws_key" "replicated_key" {
  alias       = ["alias"]
  region      = "us-north-1"
  replicate_key {
    import_key_material = true
    key_id              = ciphertrust_aws_key.aws_external_multiregion_key.key_id
  }
  origin = "EXTERNAL"
}
