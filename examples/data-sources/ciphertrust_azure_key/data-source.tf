# Retrieve details using the Azure key ID
data "ciphertrust_azure_key" "by_azure_key_id" {
  azure_key_id = "kid"
}

# Retrieve details using the key name and vault
data "ciphertrust_azure_key" "by_name_and_vault" {
  name      = "key-name"
  key_vault = "vault-name::subscription-id"
}
