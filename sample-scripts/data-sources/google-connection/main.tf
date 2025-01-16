terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.7-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "google-connection-${lower(random_id.random.hex)}"
}

# Create a GCP connection
resource "ciphertrust_gcp_connection" "connection" {
  description = "Description of the Google Cloud connection"
  key_file    = var.gcp_key_file
  meta        = { key = "value" }
  name        = local.connection_name
}

# Add a GCP key ring
resource "ciphertrust_gcp_keyring" "gcp_keyring" {
  gcp_connection = ciphertrust_gcp_connection.connection.name
  name           = var.keyring
  project_id     = var.gcp_project
}

# Get the GCP connection data using the connection name
data "ciphertrust_gcp_connection" "connection_data" {
  name = ciphertrust_gcp_connection.connection.name
}
output "gcp_connection_data" {
  value = data.ciphertrust_gcp_connection.connection_data
}
