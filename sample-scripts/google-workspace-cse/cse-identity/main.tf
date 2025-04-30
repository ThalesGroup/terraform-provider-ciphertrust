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
  identity_issuer_only_name     = "cse-identity-issuer-only-${lower(random_id.random.hex)}"
  identity_issuer_and_jwks_name = "cse-identity-issuer-and-jwks-${lower(random_id.random.hex)}"
  identity_open_id_only_name    = "cse-identity-open-id-only-${lower(random_id.random.hex)}"
  identity_with_all_name        = "cse-identity-with-all-${lower(random_id.random.hex)}"
}

# Create a CSE identity using only issuer
resource "ciphertrust_gwcse_identity" "cse_identity_issuer_only" {
  name   = local.identity_issuer_only_name
  issuer = var.issuer
}
output "cse_identity_issuer_only" {
  value = ciphertrust_gwcse_identity.cse_identity_issuer_only
}

# Create a CSE identity using issuer and jwks_url
resource "ciphertrust_gwcse_identity" "cse_identity_issuer_and_jwks" {
  name     = local.identity_issuer_and_jwks_name
  issuer   = var.issuer
  jwks_url = var.jwks_url
}
output "cse_identity_issuer_and_jwks" {
  value = ciphertrust_gwcse_identity.cse_identity_issuer_and_jwks
}

# Create a CSE identity using only open_id_configuration_url
resource "ciphertrust_gwcse_identity" "cse_identity_open_id" {
  name                      = local.identity_open_id_only_name
  open_id_configuration_url = var.open_id_configuration_url
}
output "cse_identity_open_id" {
  value = ciphertrust_gwcse_identity.cse_identity_open_id
}

# Create a CSE identity using all input parameters
resource "ciphertrust_gwcse_identity" "cse_identity_with_all" {
  name                      = local.identity_with_all_name
  issuer                    = var.issuer
  jwks_url                  = var.jwks_url
  open_id_configuration_url = var.open_id_configuration_url
}
output "cse_identity_with_all" {
  value = ciphertrust_gwcse_identity.cse_identity_with_all
}
