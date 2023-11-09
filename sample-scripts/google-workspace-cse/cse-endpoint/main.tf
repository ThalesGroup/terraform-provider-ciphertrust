terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.2-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  identity_name = "cse-identity-${lower(random_id.random.hex)}"
  endpoint_name = "cse-endpoint-${lower(random_id.random.hex)}"
}

# Create a CSE identity
resource "ciphertrust_gwcse_identity" "cse_identity" {
  name   = local.identity_name
  issuer = var.issuer
}
output "cse_identity" {
  value = ciphertrust_gwcse_identity.cse_identity
}

# Create a CSE endpoint
resource "ciphertrust_gwcse_endpoint" "cse_endpoint" {
  name                    = local.endpoint_name
  cse_identity_id         = [ciphertrust_gwcse_identity.cse_identity.id]
  authentication_audience = [var.authentication_audience]
  endpoint_url_hostname   = var.endpoint_url_hostname
}
output "cse_endpoint" {
  value = ciphertrust_gwcse_endpoint.cse_endpoint
}
