# Get the Azure key data using the azure key id
data "ciphertrust_azure_key" "by_azure_key_id" {
  azure_key_id = ciphertrust_azure_key.azure_key.azure_key_id
}

# Get the Azure key data using the key name only
data "ciphertrust_azure_key" "by_name" {
  name = ciphertrust_azure_key.azure_key.name
}

# Get the Azure key data using the key name and vault
data "ciphertrust_azure_key" "by_name_and_vault" {
  name      = ciphertrust_azure_key.azure_key.name
  key_vault = ciphertrust_azure_key.azure_key.key_vault
}

# Get the Azure key data for the latest version using the key name and version
data "ciphertrust_azure_key" "by_name_and_version" {
  name    = ciphertrust_azure_key.azure_key.name
  version = "-1"
}

# Get the Azure key data for the latest version using the key name and vault and version
data "ciphertrust_azure_key" "by_name_and_vault_and_version" {
  name      = ciphertrust_azure_key.azure_key.name
  key_vault = ciphertrust_azure_key.azure_key.key_vault
  version   = "-1"
}
