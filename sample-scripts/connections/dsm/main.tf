terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.11.1"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "dsm-connection-${lower(random_id.random.hex)}"
}

# Create a dsm connection
resource "ciphertrust_dsm_connection" "connection" {
  name = local.connection_name
  nodes {
    hostname    = var.dsm_ip
    certificate = var.dsm_certificate
  }
  password = var.dsm_password
  username = var.dsm_username
}
output "dsm_connection_id" {
  value = ciphertrust_dsm_connection.connection.id
}

# Add a dsm domain
resource "ciphertrust_dsm_domain" "domain" {
  dsm_connection = ciphertrust_dsm_connection.connection.id
  domain_id      = var.dsm_domain
}
output "domain" {
  value = ciphertrust_dsm_domain.domain
}
