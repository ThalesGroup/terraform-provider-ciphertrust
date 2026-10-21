terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.1.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name   = "tf-oci-rot-${lower(random_id.random.hex)}"
  key_name          = "tf-oci-rot-key-${lower(random_id.random.hex)}"
  rotation_job_name = "tf-oci-rotation-${lower(random_id.random.hex)}"
  sync_vault_job    = "tf-oci-sync-vault-${lower(random_id.random.hex)}"
  sync_all_job      = "tf-oci-sync-all-${lower(random_id.random.hex)}"
}

# Define an OCI connection
resource "ciphertrust_oci_connection" "oci_connection" {
  key_file            = var.oci_key_file
  name                = local.connection_name
  pub_key_fingerprint = var.oci_pub_key_fingerprint
  region              = var.oci_region
  tenancy_ocid        = var.oci_tenancy_ocid
  user_ocid           = var.oci_user_ocid
}

# Define an OCI vault
resource "ciphertrust_oci_vault" "vault" {
  connection_id = ciphertrust_oci_connection.oci_connection.id
  vault_id      = var.oci_vault_ocid
  region        = var.oci_region
}

# Define a scheduler that rotates OCI keys
resource "ciphertrust_scheduler" "rotation" {
  name      = local.rotation_job_name
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * fri"
  cckm_key_rotation_params = {
    cloud_name = "oci"
    expiration = "365d"
    expire_in  = "10d"
  }
}

# Define a scheduler that synchronizes the keys of the vault
resource "ciphertrust_scheduler" "sync_vault" {
  name      = local.sync_vault_job
  operation = "cckm_synchronization"
  run_at    = "0 9 * * sat"
  cckm_synchronization_params = {
    cloud_name = "oci"
    oci_vaults = [ciphertrust_oci_vault.vault.id]
  }
}

# Define a scheduler that synchronizes all OCI keys
resource "ciphertrust_scheduler" "sync_all" {
  name      = local.sync_all_job
  operation = "cckm_synchronization"
  run_at    = "0 9 * * sun"
  cckm_synchronization_params = {
    cloud_name      = "oci"
    synchronize_all = true
  }
}

# Define a native key.
# enable_auto_rotation cannot be set when a key is created. Run terraform apply once,
# then run terraform apply -var="enable_rotation=true" to register the key with the
# rotation scheduler. Run terraform apply -var="enable_rotation=false" to unregister it.
resource "ciphertrust_oci_key" "key" {
  name  = local.key_name
  vault = ciphertrust_oci_vault.vault.id
  oci_key_params = {
    algorithm       = "AES"
    compartment_id  = ciphertrust_oci_vault.vault.compartment_id
    length          = 32
    protection_mode = "SOFTWARE"
  }
  enable_auto_rotation = var.enable_rotation ? {
    job_config_id = ciphertrust_scheduler.rotation.id
    key_source    = "ciphertrust"
  } : null
}
