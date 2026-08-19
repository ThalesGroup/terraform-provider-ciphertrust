terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {
  address  = "https://10.10.10.10"
  username = "admin"
  password = "ChangeMe101!"
}

data "ciphertrust_oci_connection_list" "example_oci_connection" {
  filters = {
    name = "oci-connection"
  }
  # Similarly can provide 'id', 'products', 'meta_contains' etc to further
  # narrow down the existing OCI connections.
}

output "oci_connection_details" {
  value = data.ciphertrust_oci_connection_list.example_oci_connection
}
