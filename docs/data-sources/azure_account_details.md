---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_azure_account_details Data Source - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_azure_account_details (Data Source)

This data-source provides some Azure details associated with a [ciphertrust_aws_connection](https://registry.terraform.io/providers/ThalesGroup/ciphertrust/latest/docs/resources/aws_connection) resource.

The details can optionally be used when creating a [ciphertrust_azure_vault](https://registry.terraform.io/providers/ThalesGroup/ciphertrust/latest/docs/resources/azure_vault) resource.


## Example Usage

```terraform
# Create an Azure connection 
resource "ciphertrust_azure_connection" "azure_connection" {
  name          = "connection-name"
  client_id     = "azure-client-id"
  client_secret = "azure-client-secret"
  tenant_id     = "azure-tenant-id"
}

data "ciphertrust_azure_account_details" "subscriptions" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
}

resource "ciphertrust_azure_vault" "azure_vault" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = data.ciphertrust_azure_account_details.subscriptions.subscription_id
  name             = "azure-vault"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `azure_connection` (String) Name or ID of the Azure connection.

### Optional

- `display_name` (String) Display name of the Subscription. If not set the first subscription is returned.

### Read-Only

- `id` (String) Azure Subscription ID.
- `subscription_id` (String) CipherTrust ID for the subscription.


