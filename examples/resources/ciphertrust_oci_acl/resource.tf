# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an OCI connection resource
# with the CipherTrust provider

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust Manager resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.0-pre3"
    }
  }
}

# Configure the CipherTrust provider for authentication
provider "ciphertrust" {
  # The address of the CipherTrust Manager appliance (replace with the actual address)
  address = "https://10.10.10.10"

  # Username for authenticating with the CipherTrust Manager appliance
  username = "admin"

  # Password for authenticating with the CipherTrust Manager appliance
  password = "ChangeMe101!"
}

# Define an OCI connection
resource "ciphertrust_oci_connection" "oci_connection" {
  key_file            = "path-to-or-contents-of-oci-key-file"
  name                = "connection-name"
  pub_key_fingerprint = "public-key-fingerprint"
  region              = "oci-region"
  tenancy_ocid        = "tenancy-ocid"
  user_ocid           = "user-ocid"
}

# Define an OCI vault
resource "ciphertrust_oci_vault" "vault" {
  region        = "oci-region"
  connection_id = ciphertrust_oci_connection.oci_connection.name
  vault_id      = "vault-ocid"
}

# Define an ACL for a CipherTrust Manager user
resource "ciphertrust_oci_acl" "user_acl" {
  vault_id = "ciphertrust-vault-id"
  user_id  = "ciphertrust-user-id"
  actions  = ["view", "keycreate", "keyupdate", "keydelete"]
}

# Define an ACL for a CipherTrust Manager group
resource "ciphertrust_oci_acl" "user_acl" {
  vault_id = "ciphertrust-vault-id"
  group    = "ciphertrust-group-name"
  actions  = ["keycreate", "keyupdate", "keydelete"]
}

# Import an existing OCI ACL for a user

## Define a resource for and existing ACL with data matching the existing ACL
resource "ciphertrust_oci_acl" "imported_user_acl" {
  vault_id = "ciphertrust-vault-id"
  user_id  = "ciphertrust-user-id"
  actions  = ["keycreate", "keyupdate", "keydelete"]
}

## Run the terraform import command
terraform import ciphertrust_oci_acl.imported_user_acl "vault-id::user::user-id"
For example: terraform import ciphertrust_oci_acl.imported_user_acl fd466e89-dc81-4d8d-bc3f-208b5f8e78a0:user:local|2f94d5b4-8563-464a-b32b-19aa50878073

# Import an existing OCI ACL for a group

## Define a resource for an existing ACL with data matching the group's ACL
resource "ciphertrust_oci_acl" "imported_group_acl" {
  vault_id = "ciphertrust-vault-id"
  group    = "ciphertrust-group-name"
  actions  = ["keycreate", "keyupdate", "keydelete"]
}

## Run the terraform import command
terraform import ciphertrust_oci_acl.imported_group_acl "vault-id::group::group-name"
For example: terraform import ciphertrust_oci_acl.imported_group_acl "fd466e89-dc81-4d8d-bc3f-208b5f8e78a0:group:CCKM Users"
