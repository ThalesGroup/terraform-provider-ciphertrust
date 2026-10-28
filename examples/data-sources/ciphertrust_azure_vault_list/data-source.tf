# List Azure Key Vaults in the CipherTrust Manager database.
# Use ciphertrust_azure_vault_details to discover vaults live from Azure.

# No filter - return all vaults (default limit: 10).
data "ciphertrust_azure_vault_list" "all" {}

# Filter by Azure subscription ID.
data "ciphertrust_azure_vault_list" "by_subscription" {
  filters = {
    subscription_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  }
}

# Key Vaults only, all results sorted by most recently created.
data "ciphertrust_azure_vault_list" "key_vaults" {
  filters = {
    type  = "vault"
    sort  = "-createdAt"
    limit = "-1"
  }
}

# Managed HSM vaults only.
data "ciphertrust_azure_vault_list" "managed_hsms" {
  filters = {
    type = "managedHsm"
  }
}

# Look up a specific vault by its CipherTrust Manager resource name.
# The name has the format "vault-name::subscription-id".
# The cckm_vault_name computed attribute on ciphertrust_azure_vault produces this value.
data "ciphertrust_azure_vault_list" "specific" {
  filters = {
    name = "my-key-vault::xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  }
}
