terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.5-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  oci_issuer_name = "oci-issuer-${lower(random_id.random.hex)}"
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

# Create an external vault that will accept CipherTrust Manager keys only
resource "ciphertrust_oci_external_vault" "external_vault" {
  client_application_id = var.client_application_id
  issuer_id             = ciphertrust_oci_issuer.issuer.id
  source_key_tier       = "local"
  tenancy_ocid          = ciphertrust_oci_tenancy.tenancy.tenancy_ocid
  vault_name            = local.oci_vault_name
}
