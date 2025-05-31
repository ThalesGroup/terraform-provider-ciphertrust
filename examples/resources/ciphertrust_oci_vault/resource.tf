# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an OCI Vault resource
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

# Define an OCI connection
resource "ciphertrust_oci_connection" "connection" {
  key_file            = "path-to-or-contents-of-oci-key-file"
  name                = "example-name"
  pub_key_fingerprint = "public-key-fingerprint"
  region              = "oci-region"
  tenancy_ocid        = "tenancy-ocid"
  user_ocid           = "user-ocid"
}

# Define an OCI vault
resource "ciphertrust_oci_vault" "vault" {
  region        = "oci-region"
  connection_id = ciphertrust_oci_connection.connection.name
  vault_id      = "vault-ocid"
}

# Define an OCI vault, using available datasources

data "ciphertrust_get_oci_regions" "regions" {
  connection_id = ciphertrust_oci_connection.connection.name
}

data "ciphertrust_get_oci_compartments" "compartments" {
  connection_id = ciphertrust_oci_connection.connection.name
}

data "ciphertrust_get_oci_vaults" "vaults" {
  connection_id = ciphertrust_oci_connection.connection.name
  compartment_id = data.ciphertrust_get_oci_compartments.compartments.compartments.0.id
  region         = data.ciphertrust_get_oci_regions.regions.regions.0
}

resource "ciphertrust_oci_vault" "vault" {
  region        = data.ciphertrust_get_oci_regions.regions.regions.0
  connection_id = ciphertrust_oci_connection.connection.name
  vault_id      = data.ciphertrust_get_oci_vaults.vaults.vaults.0.vault_id
}

# Import an existing OCI vault

## Define a resource for an existing vault with values matching the vault
resource "ciphertrust_oci_vault" "imported_vault" {
  region        = "region"
  connection_id = "connection-name"
  vault_id      = "vault_ocid"
}

## Run the terraform import command
terraform import ciphertrust_oci_vault.imported_vault ciphertrust-manager-oci-vault-resource-id
For example: terraform import ciphertrust_oci_vault.imported_vault af0c0c2c-242f-4c23-ab82-76d32d54901b
