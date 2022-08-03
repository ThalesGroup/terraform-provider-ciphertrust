# Retrieve details using the Terraform resource ID
data "ciphertrust_azure_key" "by_resource_id" {
  id = ciphertrust_azure_key.azure_key.id
}

# Retrieve details using the Azure key ID
data "ciphertrust_azure_key" "by_azure_key_id" {
  azure_key_id = ciphertrust_azure_key.azure_key.azure_key_id
}

# Retrieve details using the key name and vault
data "ciphertrust_azure_key" "by_name_and_vault" {
  name      = ciphertrust_azure_key.azure_key.name
  key_vault = format("%s::%s", "vault_name", "subscription")
}
