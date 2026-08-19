# Pre-requisites for an OCI key - OCI connection, OCI Vault

# Define an OCI connection
resource "ciphertrust_oci_connection" "connection" {
  key_file            = "path-to-or-contents-of-oci-key-file"
  name                = "name"
  pub_key_fingerprint = "public-key-fingerprint"
  region              = "region"
  tenancy_ocid        = "tenancy-ocid"
  user_ocid           = "user-ocid"
}

# Define an OCI Vault
resource "ciphertrust_oci_vault" "vault" {
  connection_id = ciphertrust_oci_connection.connection.id
  vault_id      = "vault-ocid"
  region        = "region"
}

# Define a CipherTrust Manager source key
resource "ciphertrust_cm_key" "source_key" {
  name       = "name"
  algorithm  = "RSA"
  usage_mask = 60
  key_size   = 2048
}

# Define an OCI BYOK key
resource "ciphertrust_oci_byok_key" "key" {
  # Required parameters
  name          = "name"
  source_key_id = ciphertrust_cm_key.source_key.id
  vault         = ciphertrust_oci_vault.vault.id
  oci_key_params = {
    compartment_id  = "compartment-ocid"
    protection_mode = "SOFTWARE"
    # Optional oci_key_params
    defined_tags = [
      {
        tag = "oci-namespace"
        values = {
          key-tag = "key-value"
        }
      }
    ]
    freeform_tags = {
      key-tag = "key-value"
    }
  }
  # Optional parameters
  schedule_for_deletion_days = 14
  source_key_tier            = "local"
}

# After creation, enable auto-rotation by updating the resource.
# Create a key rotation scheduler and attach it to the key:
resource "ciphertrust_scheduler" "scheduled_rotation" {
  cckm_key_rotation_params = {
    cloud_name = "oci"
    expiration = "365d"
    expire_in  = "10d"
  }
  name      = "name"
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * fri"
  run_on    = "any"
}

resource "ciphertrust_oci_byok_key" "key" {
  name          = "name"
  source_key_id = ciphertrust_cm_key.source_key.id
  vault         = ciphertrust_oci_vault.vault.id
  oci_key_params = {
    compartment_id  = "compartment-ocid"
    protection_mode = "SOFTWARE"
  }
  enable_auto_rotation = {
    job_config_id = ciphertrust_scheduler.scheduled_rotation.id
  }
  enable_key = false
}

