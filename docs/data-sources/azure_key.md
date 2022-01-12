---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_azure_key Data Source - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_azure_key (Data Source)



## Example Usage

```terraform
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
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- **azure_key_id** (String) Input parameter. Key identifier.
- **id** (String) The ID of this resource.
- **key_vault** (String) Input parameter. Name of the Azure vault containing the key in the format of vault_name::subscription_id. Can be used with name and optionally version to specify the key.
- **name** (String) Input parameter. Key name. Can be optionally be used with vault and\or version to specify the key.
- **version** (String) Input parameter. Key version. If ommitted the latest version is retrieved unless only azure_key_id is specified in which case the version is already specified.

### Read-Only

- **activation_date** (String) Date of key activation.
- **backup** (String) CipherTrust ID of the key's backup.
- **backup_at** (String) Date the key was backed up.
- **cloud_name** (String) Azure cloud.
- **created_at** (String) Date the key was created.
- **created_by** (String) Client ID which created the key.
- **curve** (String) Curve name of an EC or EC-HSM key.
- **deleted** (Boolean) True if the key is deleted.
- **enabled** (Boolean) True if the key is enabled.
- **expiration_date** (String) Date of key expiry.
- **gone** (Boolean) True if the key is not managed by the connection.
- **key_id** (String) CipherTrust Key ID.
- **key_material_origin** (String) Key material origin of an uploaded or imported key.
- **key_ops** (List of String) Allowed key operations for asymmetric keys.
- **key_size** (Number) Size of asymmetric keys.
- **key_soft_deleted_in_azure** (Boolean) True if the key is soft-deleted in Azure.
- **key_type** (String) Key type.
- **key_vault_id** (String) CipherTrust vault ID.
- **labels** (Map of String) A list of key:value pairs associated with the key.
- **local_key_id** (String) CipherTrust key identifier of the external key.
- **local_key_name** (String) CipherTrust key name of the external key.
- **modified_by** (String) Client ID which modified the key.
- **recovery_level** (String) Recovery level of the key.
- **region** (String) Azure region of the key.
- **soft_delete_enabled** (Boolean) True if soft-delete is enabled for the key.
- **status** (String) Status of the key.
- **synced_at** (String) Date the key was synchronized.
- **tags** (Map of String) A list of tags assigned to the key.
- **tenant** (String) Azure Tenant.
- **updated_at** (String) Date the key was last updated.
- **version_count** (Number) Number of versions of the key.

