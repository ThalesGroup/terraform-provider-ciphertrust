terraform {
  required_providers {
    ciphertrust = {
      source = "thales.com/terraform/ciphertrust"
      version = "0.10.5-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  ekm_min_params_name = "ekm-min-params-${lower(random_id.random.hex)}"
  ekm_name            = "ekm-${lower(random_id.random.hex)}"
  ude_ekm_name        = "ekm-ude-${lower(random_id.random.hex)}"
}

# EKM endpoints require a Google Project to exist in CipherTrust Manager.
# Creating a GCP Connection will add a Google Project but if a connection is not required a project can be added.

# Add a Google Project
resource "ciphertrust_google_project" "project" {
  project_id = var.gcp_project
}
output "gcp_project_id" {
  value = ciphertrust_google_project.project.id
}

# Create an EKM endpoint with minimum parameters
resource "ciphertrust_ekm_endpoint" "ekm_min_params" {
  depends_on = [
    ciphertrust_google_project.project,
  ]
  name             = local.ekm_min_params_name
  key_uri_hostname = var.key_uri_hostname
  policy {
    clients = [var.policy_client]
  }
}
output "ekm_min_params" {
  value = ciphertrust_ekm_endpoint.ekm_min_params
}

# Create an EKM endpoint
resource "ciphertrust_ekm_endpoint" "ekm" {
  depends_on = [
    ciphertrust_google_project.project,
  ]
  name             = local.ekm_name
  key_uri_hostname = var.key_uri_hostname
  policy {
    clients                = [var.policy_client]
    justification_required = true
    justification_reason   = [var.justification_reason]
  }
  key_type  = "asymmetric"
  algorithm = "EC_SIGN_P256_SHA256"
}
output "ekm" {
  value = ciphertrust_ekm_endpoint.ekm
}

# Create an EKM UDE endpoint
resource "ciphertrust_ekm_endpoint" "ude_ekm" {
  depends_on = [
    ciphertrust_google_project.project,
  ]
  name                    = local.ude_ekm_name
  key_uri_hostname        = var.key_uri_hostname
  cvm_required_for_unwrap = true
  cvm_required_for_wrap   = true
  endpoint_type           = "ekm-ude"
  policy {
    clients                    = [var.policy_client]
    justification_required     = true
    justification_reason       = [var.justification_reason]
    attestation_zones          = [var.attestation_zone]
    attestation_project_ids    = [var.attestation_project_id]
    attestation_instance_names = [var.attestation_instance_name]
  }
}
output "ude_ekm" {
  value = ciphertrust_ekm_endpoint.ude_ekm
}
