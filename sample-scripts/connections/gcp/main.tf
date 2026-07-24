terraform {
  required_providers {
    ciphertrust = {
      source = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {
	address = "https://10.10.10.10"
	username = "admin"
	password = "ChangeMe101!"
}

resource "ciphertrust_gcp_connection" "gcp_connection" {
  name        = "gcp-connection"
  products = [
    "cckm"
  ]
  // key file data or key file name which consists service account data
  key_file    = "{\"type\":\"service_account\",\"private_key_id\":\"paafkhjbfbhfadb2324e324dasfdsf\",\"private_key\":\"-----BEGIN RSA PRIVATE KEY-----\\n.....\\n-----END RSA PRIVATE KEY-----\\n\\n\",\"client_email\":\"test@some-project.iam.gserviceaccount.com\"}"
  cloud_name  = "gcp"
  description = "connection description"
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1" = "custom_value1"
    "customer_meta_key2" = "custom_value2"
  }

}

output "gcp_connection_id" {
  value = ciphertrust_gcp_connection.gcp_connection.id
}

output "gcp_connection_name" {
  value = ciphertrust_gcp_connection.gcp_connection.name
}