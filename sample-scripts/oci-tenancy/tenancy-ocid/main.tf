terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.11.2"
    }
  }
}

provider "ciphertrust" {}

# Create an OCI tenancy resource using tenancy OCID and name
resource "ciphertrust_oci_tenancy" "tenancy" {
  tenancy_ocid = var.tenancy_ocid
  tenancy_name = var.tenancy_name
}
