# List Azure subscriptions in the CipherTrust Manager database.
# A subscription is added automatically when its first vault is created
# and removed when its last vault is deleted.
# Use ciphertrust_azure_subscription_details to query subscriptions live from Azure.

# No filter - return all subscriptions (default limit: 10).
data "ciphertrust_azure_subscription_list" "all" {}

# Filter by Azure subscription ID.
data "ciphertrust_azure_subscription_list" "by_id" {
  filters = {
    subscriptionId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  }
}

# Filter by display name.
data "ciphertrust_azure_subscription_list" "by_name" {
  filters = {
    displayName = "My Azure Subscription"
  }
}

# Return all matches sorted by most recently updated.
data "ciphertrust_azure_subscription_list" "all_sorted" {
  filters = {
    sort  = "-updatedAt"
    limit = "-1"
  }
}
