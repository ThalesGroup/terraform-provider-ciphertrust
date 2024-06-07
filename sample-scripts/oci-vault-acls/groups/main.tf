terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.5-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  oci_connection_name = "oci-connection-${lower(random_id.random.hex)}"
  oci_issuer_name     = "oci-issuer-${lower(random_id.random.hex)}"
  oci_vault_name      = "oci-vault-${lower(random_id.random.hex)}"
  user_name           = "oci-user-${lower(random_id.random.hex)}"
  group_name          = "oci-group-${lower(random_id.random.hex)}"
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

# Add an issuer
resource "ciphertrust_oci_issuer" "issuer" {
  name              = local.oci_issuer_name
  openid_config_url = var.openid_config_url
}

# Create an external vault
resource "ciphertrust_oci_external_vault" "vault" {
  client_application_id = var.client_application_id
  connection_id         = ciphertrust_oci_connection.oci_connection.id
  issuer_id             = ciphertrust_oci_issuer.issuer.id
  policy_file           = var.oci_vault_policy_file
  vault_name            = local.oci_vault_name
}

# Create a user
resource "ciphertrust_user" "group_user" {
  username = local.user_name
  password = "Test0123#"
}

# Add the user to the CCKM Users group
resource "ciphertrust_groups" "cckm_users" {
  name = "CCKM Users"
  user_ids = [
    ciphertrust_user.group_user.id,
  ]
}

# Create a group and add the user
resource "ciphertrust_groups" "group" {
  name     = local.group_name
  user_ids = [ciphertrust_user.group_user.id]
}

# Add some acls for the group
resource "ciphertrust_oci_acl" "group_acls" {
  vault_id = ciphertrust_oci_external_vault.vault.id
  group    = ciphertrust_groups.group.id
  actions  = ["viewhyokkey", "hyokkeycreate", "hyokkeydelete"]
}
