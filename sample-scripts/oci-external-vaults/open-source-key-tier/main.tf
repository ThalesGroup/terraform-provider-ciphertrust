terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.10-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  oci_connection_name = "oci-connection-${lower(random_id.random.hex)}"
  oci_issuer_name     = "oci-issuer-${lower(random_id.random.hex)}"
  oci_vault_name      = "oci-vault-${lower(random_id.random.hex)}"
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

# Add an issuer
resource "ciphertrust_oci_issuer" "issuer" {
  name              = local.oci_issuer_name
  openid_config_url = var.openid_config_url
}

# Create an external vault that will accept either CipherTrust or hsm-luna keys
# This vault will use the tenancy of the connection.
resource "ciphertrust_oci_external_vault" "external_vault" {
  client_application_id = var.client_application_id
  connection_id         = ciphertrust_oci_connection.oci_connection.id
  issuer_id             = ciphertrust_oci_issuer.issuer.id
  policy_file           = var.oci_vault_policy_file
  vault_name            = local.oci_vault_name
}
