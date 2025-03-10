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
  oci_connection_name = "oci-connection-${lower(random_id.random.hex)}"
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
