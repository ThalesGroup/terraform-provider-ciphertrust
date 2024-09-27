terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.6-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  gcp_connection_name = "gcp-connection-${lower(random_id.random.hex)}"
  dsm_connection_name = "dsm-connection-${lower(random_id.random.hex)}"
  key_name            = "dsm-aes-version-${lower(random_id.random.hex)}"
}

# Create a GCP connection
resource "ciphertrust_gcp_connection" "gcp_connection" {
  key_file = var.gcp_key_file
  name     = local.gcp_connection_name
}

# Add a GCP key ring
resource "ciphertrust_gcp_keyring" "keyring" {
  gcp_connection = ciphertrust_gcp_connection.gcp_connection.id
  name           = var.keyring
  project_id     = var.gcp_project
}

resource "ciphertrust_dsm_connection" "dsm_connection" {
  name = local.dsm_connection_name
  nodes {
    hostname    = var.dsm_ip
    certificate = var.dsm_certificate
  }
  password = var.dsm_password
  username = var.dsm_username
}

resource "ciphertrust_dsm_domain" "dsm_domain" {
  dsm_connection = ciphertrust_dsm_connection.dsm_connection.id
  domain_id      = var.dsm_domain
}

# Create a DSM symmetric key
resource "ciphertrust_dsm_key" "symmetric_dsm_key" {
  name            = local.key_name
  algorithm       = "AES256"
  domain          = ciphertrust_dsm_domain.dsm_domain.id
  encryption_mode = "CBC"
  extractable     = true
  object_type     = "symmetric"
}

# Create a Google Cloud symmetric key and add a new version
resource "ciphertrust_gcp_key" "gcp_aes_key" {
  add_version {
    is_native       = false
    algorithm       = "GOOGLE_SYMMETRIC_ENCRYPTION"
    source_key_id   = ciphertrust_dsm_key.symmetric_dsm_key.id
    source_key_tier = "dsm"
  }
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring  = ciphertrust_gcp_keyring.keyring.id
  name      = local.key_name
}
output "gcp_aes_key" {
  value = ciphertrust_gcp_key.gcp_aes_key
}
