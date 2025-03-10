terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.8-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  oci_connection_name = "oci-connection-${lower(random_id.random.hex)}"
  hsm_connection_name = "hsm-connection-${lower(random_id.random.hex)}"
  oci_issuer_name     = "oci-issuer-${lower(random_id.random.hex)}"
  oci_vault_name      = "oci-vault-${lower(random_id.random.hex)}"
  key_name            = "oci-key-${lower(random_id.random.hex)}"
  version_name        = "oci-version-${lower(random_id.random.hex)}"
  rotation_job_name   = "oci-key-rotation-${lower(random_id.random.hex)}"
}

# Create an OCI Cloud connection
resource "ciphertrust_oci_connection" "oci_connection" {
  name                = local.oci_connection_name
  key_file            = var.oci_key_file
  pub_key_fingerprint = var.pub_key_fingerprint
  region              = var.region
  tenancy_ocid        = var.tenancy_ocid
  user_ocid           = var.user_ocid
}

# Create a hsm network server
resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = var.hsm_hostname
  hsm_certificate = var.hsm_certificate
}

# Create a hsm-luna connection
resource "ciphertrust_hsm_connection" "hsm_connection" {
  hostname  = var.hsm_hostname
  server_id = ciphertrust_hsm_server.hsm_server.id
  name      = local.hsm_connection_name
  partitions {
    partition_label = var.hsm_partition_label
    serial_number   = var.hsm_partition_serial_number
  }
  partition_password = var.hsm_partition_password
}

# Add a partition to connection
resource "ciphertrust_hsm_partition" "hsm_partition" {
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
}

# Add an oci issuer
resource "ciphertrust_oci_issuer" "issuer" {
  name              = local.oci_issuer_name
  openid_config_url = var.openid_config_url
}

# Create an external vault
resource "ciphertrust_oci_external_vault" "external_vault" {
  client_application_id = var.client_application_id
  connection_id         = ciphertrust_oci_connection.oci_connection.id
  issuer_id             = ciphertrust_oci_issuer.issuer.id
  policy_file           = var.oci_vault_policy_file
  vault_name            = local.oci_vault_name
}

# Create a hsm-luna key
resource "ciphertrust_hsm_key" "hsm_luna_key" {
  hyok_key     = true
  label        = local.key_name
  mechanism    = "CKM_AES_KEY_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
  key_size     = 256
}

# Create scheduled rotation job to run every Saturday at 9 am
resource "ciphertrust_scheduler" "rotation_job" {
  cckm_key_rotation_params {
    cloud_name = "oci"
  }
  name      = local.rotation_job_name
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}

# Add key with rotation enabled to vault
resource "ciphertrust_oci_external_key" "external_key" {
  cckm_vault_id = ciphertrust_oci_external_vault.external_vault.id
  enable_rotation {
    hsm_partition_id = ciphertrust_hsm_partition.hsm_partition.id
    job_config_id    = ciphertrust_scheduler.rotation_job.id
    key_source       = "hsm-luna"
  }
  name            = local.key_name
  source_key_id   = ciphertrust_hsm_key.hsm_luna_key.id
  source_key_tier = "hsm-luna"
}
