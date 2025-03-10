terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.9-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  cm_key_name       = "cm-key-${lower(random_id.random.hex)}"
  oci_key_name      = "oci-key-${lower(random_id.random.hex)}"
  oci_issuer_name   = "oci-issuer-${lower(random_id.random.hex)}"
  oci_vault_name    = "oci-vault-${lower(random_id.random.hex)}"
  rotation_job_name = "oci-key-rotation-${lower(random_id.random.hex)}"
  tenancy_name      = "oci-tenancy-${lower(random_id.random.hex)}"
}

# Add an issuer
resource "ciphertrust_oci_issuer" "issuer" {
  name              = local.oci_issuer_name
  openid_config_url = var.openid_config_url
}

# Add a tenancy resource
resource "ciphertrust_oci_tenancy" "tenancy" {
  tenancy_ocid = var.tenancy_ocid
  tenancy_name = local.tenancy_name
}

# Create an external vault that will only accept keys from any key source
resource "ciphertrust_oci_external_vault" "external_vault" {
  depends_on            = [ciphertrust_oci_tenancy.tenancy]
  client_application_id = var.client_application_id
  issuer_id             = ciphertrust_oci_issuer.issuer.id
  tenancy_ocid          = ciphertrust_oci_tenancy.tenancy.tenancy_ocid
  vault_name            = local.oci_vault_name
}

# Create a CipherTrust key
resource "ciphertrust_cm_key" "cm_key" {
  name         = local.cm_key_name
  algorithm    = "AES"
  undeletable  = true
  unexportable = true
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

# Create an external key, enabling rotation using CipherTrust Manager keys at the same time
resource "ciphertrust_oci_external_key" "external_key" {
  cckm_vault_id = ciphertrust_oci_external_vault.external_vault.id
  enable_rotation {
    job_config_id = ciphertrust_scheduler.rotation_job.id
    key_source    = "ciphertrust"
  }
  name          = local.oci_key_name
  source_key_id = ciphertrust_cm_key.cm_key.id
  policy_file   = var.oci_key_policy_file
}
