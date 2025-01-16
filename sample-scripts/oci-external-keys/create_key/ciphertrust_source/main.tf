terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.7-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  cm_key_name_1   = "cm-key-1-${lower(random_id.random.hex)}"
  cm_key_name_2   = "cm-key-2-${lower(random_id.random.hex)}"
  oci_issuer_name = "oci-issuer-${lower(random_id.random.hex)}"
  oci_key_name    = "oci-key-${lower(random_id.random.hex)}"
  oci_vault_name  = "oci-vault-${lower(random_id.random.hex)}"
  tenancy_name    = "oci-tenancy-${lower(random_id.random.hex)}"
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

# Create an external vault that will only accept CipherTrust Manager keys
resource "ciphertrust_oci_external_vault" "external_vault" {
  depends_on            = [ciphertrust_oci_tenancy.tenancy]
  client_application_id = var.client_application_id
  issuer_id             = ciphertrust_oci_issuer.issuer.id
  source_key_tier       = "local"
  tenancy_ocid          = ciphertrust_oci_tenancy.tenancy.tenancy_ocid
  vault_name            = local.oci_vault_name
}

# Create a CipherTrust key
resource "ciphertrust_cm_key" "cm_key_1" {
  name         = local.cm_key_name_1
  algorithm    = "AES"
  undeletable  = true
  unexportable = true
}

# Add key to the external vault
resource "ciphertrust_oci_external_key" "external_key" {
  cckm_vault_id = ciphertrust_oci_external_vault.external_vault.id
  name          = local.oci_key_name
  source_key_id = ciphertrust_cm_key.cm_key_1.id
  policy_file   = var.oci_key_policy_file
}

# Create another CipherTrust key for another version of the external key
resource "ciphertrust_cm_key" "cm_key_2" {
  name         = local.cm_key_name_2
  algorithm    = "AES"
  undeletable  = true
  unexportable = true
}

# Add another version to the OCI key
resource "ciphertrust_oci_external_key_version" "second_version" {
  cckm_key_id   = ciphertrust_oci_external_key.external_key.id
  source_key_id = ciphertrust_cm_key.cm_key_2.id
}
