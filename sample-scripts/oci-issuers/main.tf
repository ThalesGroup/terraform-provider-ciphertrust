terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.5-beta"
    }
  }
}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  issuer_name_ex1               = "unprotected_openid-${lower(random_id.random.hex)}"
  issuer_name_ex2               = "protected_openid-${lower(random_id.random.hex)}"
  issuer_name_ex3               = "unprotected_jwks-${lower(random_id.random.hex)}"
  issuer_name_ex4               = "protected_jwks-${lower(random_id.random.hex)}"
  unprotected_openid_config_url = "unprotected_openid_config_url"
  protected_openid_config_url   = "protected_openid_config_url"
  oci_client_id                 = "oci_client_id"
  oci_client_secret             = "oci_client_secret"
  unprotected_jwks_uri          = "unprotected_jwks_uri"
  oci_issuer                    = "https://identity.oraclecloud.com/"
  protected_jwks_uri            = "protected_jwks_uri"
}

provider "ciphertrust" {}

# Create an issuer using an unprotected openid_config_url
resource "ciphertrust_oci_issuer" "unprotected_openid_config_url" {
  name              = local.issuer_name_ex1
  openid_config_url = local.unprotected_openid_config_url
}

# Create an issuer using a protected openid_config_url
resource "ciphertrust_oci_issuer" "protected_openid_config_url" {
  name               = local.issuer_name_ex2
  openid_config_url  = local.protected_openid_config_url
  jwks_uri_protected = true
  client_id          = local.oci_client_id
  client_secret      = local.oci_client_secret
}

# Create an issuer using an unprotected jwks uri and issuer
resource "ciphertrust_oci_issuer" "unprotected_jwks_and_issuer" {
  name     = local.issuer_name_ex3
  jwks_uri = local.unprotected_jwks_uri
  issuer   = local.oci_issuer
}

# Create an issuer using a protected jwks uri and issuer
resource "ciphertrust_oci_issuer" "protected_jwks_and_issuer" {
  name               = local.issuer_name_ex4
  jwks_uri           = local.protected_jwks_uri
  issuer             = local.oci_issuer
  jwks_uri_protected = true
  client_id          = local.oci_client_id
  client_secret      = local.oci_client_secret
}
