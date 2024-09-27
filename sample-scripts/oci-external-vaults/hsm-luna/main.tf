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
  hsm_connection_name = "hsm-connection-${lower(random_id.random.hex)}"
  oci_issuer_name     = "oci-issuer-${lower(random_id.random.hex)}"
  oci_vault_name      = "oci-vault-${lower(random_id.random.hex)}"
  tenancy_name        = "oci-tenancy-${lower(random_id.random.hex)}"
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

# Create an external vault that will accept keys only from the specified hsm-luna partition
resource "ciphertrust_oci_external_vault" "external_vault" {
  client_application_id = var.client_application_id
  issuer_id             = ciphertrust_oci_issuer.issuer.id
  partition_id          = ciphertrust_hsm_partition.hsm_partition.id
  policy_file           = var.oci_vault_policy_file
  source_key_tier       = "hsm-luna"
  tenancy_ocid          = ciphertrust_oci_tenancy.tenancy.tenancy_ocid
  vault_name            = local.oci_vault_name
}
