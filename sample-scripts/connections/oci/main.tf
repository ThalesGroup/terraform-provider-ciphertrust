terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {
  address  = "https://10.10.10.10"
  username = "admin"
  password = "ChangeMe101!"
}

resource "ciphertrust_oci_connection" "oci_connection" {
  name                = "oci-connection"
  key_file            = "path-to-or-contents-of-the-private-key-file-"
  pub_key_fingerprint = "public-key-fingerprint"
  region              = "oci-region"
  tenancy_ocid        = "tenancy-ocid"
  user_ocid           = "user-ocid"
}

output "oci_connection" {
  value = ciphertrust_oci_connection.oci_connection
}
