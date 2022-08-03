# Indirectly this resource is dependent on a ciphertrust_gcp_connection resource
resource "ciphertrust_gcp_connection" "gcp_connection" {
  key_file = "gcp-key-file.json"
  name     = "connection-name"
}

# This resource is dependent on a ciphertrust_gcp_keyring resource
resource "ciphertrust_gcp_keyring" "gcp_keyring" {
  gcp_connection = ciphertrust_gcp_connection.gcp_connection.name
  name           = "keyring-name"
  project_id     = "project-id"
}

# Create an asymmetric Google cloud key
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA512"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
}

# Create a symmetric Google cloud key
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
}

# Upload a CipherTrust Manager key to Google Cloud
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.cm_key.id
  }
}

# Upload a DSM key to Google Cloud
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
  upload_key {
    source_key_identifier = ciphertrust_dsm_key.dsm_key.id
    source_key_tier       = "dsm"
  }
}

# Upload a Luna-HSM key to Google Cloud
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_SIGN_PKCS1_2048_SHA256"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
  upload_key {
    source_key_identifier = ciphertrust_hsm_key.hsm_key.private_key_id
    source_key_tier       = "hsm-luna"
  }
}

# Create a new version using Google cloud
resource "ciphertrust_gcp_key" "gcp_key" {
  # Versions can be added on create or update
  add_version {
    is_native = true
  }
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA256"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
}

# Create a new version using CipherTrust Manager as the key source
resource "ciphertrust_gcp_key" "gcp_key" {
  # Versions can be added on create or update
  add_version {
    algorithm       = "GOOGLE_SYMMETRIC_ENCRYPTION"
    is_native       = false
    source_key_id   = ciphertrust_cm_key.cm_key.id
    source_key_tier = "local"
  }
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
}

# Create a new version using Luna-HSM as the key source
resource "ciphertrust_gcp_key" "gcp_key" {
  # Versions can be added on create or update
  add_version {
    is_native       = false
    algorithm       = "RSA_DECRYPT_OAEP_4096_SHA256"
    source_key_id   = ciphertrust_hsm_key.hsm_key.private_key_id
    source_key_tier = "hsm-luna"
  }
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA256"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
}

# Create a new version using a DSM as the key source
resource "ciphertrust_gcp_key" "gcp_key" {
  # Versions can be added on create or update
  add_version {
    is_native       = false
    algorithm       = "RSA_DECRYPT_OAEP_4096_SHA256"
    source_key_id   = ciphertrust_dsm_key.rsa_dsm_key.id
    source_key_tier = "dsm"
  }
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA256"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
}

# Configure Google Cloud rotation (symmetric keys only)
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm          = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring           = ciphertrust_gcp_keyring.gcp_keyring.id
  name               = "key-name"
  next_rotation_time = "2029-07-31T17:18:37.085Z"
  rotation_period    = "360000s"
}

# Schedule key rotation using Google cloud as the key source
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  # Rotation can be enabled on create or update
  enable_rotation {
    job_config_id = ciphertrust_scheduler.scheduled_rotation_job.id
    key_source    = "native"
  }
  key_ring = ciphertrust_gcp_keyring.gcp_keyring.id
  name     = "key-name"
}

# Schedule key rotation using CipherTrust Manager as the key source
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  # Rotation can be enabled on create or update
  enable_rotation {
    algorithm     = "GOOGLE_SYMMETRIC_ENCRYPTION"
    job_config_id = ciphertrust_scheduler.scheduled_rotation_job.id
    key_source    = "ciphertrust"
  }
  key_ring = ciphertrust_gcp_keyring.gcp_keyring.id
  name     = "key-name"
}

# Schedule key rotation using Luna-HSM as the key source
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_DECRYPT_OAEP_2048_SHA256"
  # Rotation can be enabled on create or update
  enable_rotation {
    algorithm        = "RSA_DECRYPT_OAEP_4096_SHA512"
    hsm_partition_id = ciphertrust_hsm_partition.hsm_partition.id
    job_config_id    = ciphertrust_scheduler.scheduled_rotation_job.id
    key_source       = "hsm-luna"
  }
  key_ring = ciphertrust_gcp_keyring.gcp_keyring.id
  name     = "key-name"
}

# Schedule key rotation using a DSM as the key source
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_SIGN_PKCS1_2048_SHA256"
  # Rotation can be enabled on create or update
  enable_rotation {
    algorithm     = "EC_SIGN_P384_SHA384"
    dsm_domain_id = ciphertrust_dsm_domain.dsm_domain.id
    job_config_id = ciphertrust_scheduler.scheduled_rotation_job.id
    key_source    = "dsm"
  }
  key_ring = ciphertrust_gcp_keyring.gcp_keyring.id
  name     = "key-name"
}
