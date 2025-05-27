# Create an OCI vault

resource "ciphertrust_oci_vault" "vault" {
  region        = "region"
  connection_id = "connection_name_or_id"
  vault_id      = "vault_ocid"
}

# Import an existing OCI vault

## Create a resource for the existing vault with data matching the existing vault
resource "ciphertrust_oci_vault" "imported_vault" {
  region        = "region"
  connection_id = "connection_name_or_id"
  vault_id      = "vault_ocid"
}

## Run the terraform import command
terraform import ciphertrust_oci_vault.imported_vault "ciphertrust_manager_oci_vault_resource_id"
