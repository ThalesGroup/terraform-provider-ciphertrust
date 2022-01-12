# Basic create key usage

resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA512"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "gcp_key_name"
}

# Upload a CipherTrust CM key to Google Cloud

resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm          = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring           = ciphertrust_gcp_keyring.gcp_keyring.id
  name               = "key_name"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.cm_key.id
  }
}

# Create a key and add a new native version

resource "ciphertrust_gcp_key" "gcp_key" {
  # Versions can be added on create or update
  add_version {
    is_native       = true
  }
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA256"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key_name"
}

# Create a key and add a new version using Hsm-Luna as the key source

resource "ciphertrust_gcp_key" "gcp_key" {
  # Versions can be added on create or update
  add_version {
    is_native       = false
    algorithm       = "RSA_DECRYPT_OAEP_2048_SHA256"
    source_key_id   = ciphertrust_hsm_key.hsm_key.private_key_id
    source_key_tier = "hsm-luna"
  }
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA256"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key_name"
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
  key_ring         = ciphertrust_gcp_keyring.gcp_keyring.id
  name             = "key_name"
}

# Schedule key rotation by Google Cloud (symmetric keys only)

resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name               = key_name
  # Can be specified on update or create
  next_rotation_time = "2022-07-31T17:18:37.085Z"
  rotation_period    = "360005s"
 }
