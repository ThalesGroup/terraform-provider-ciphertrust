---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_aws_xks_key Data Source - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_aws_xks_key (Data Source)

This data-source retrieves details of a [ciphertrust_aws_xks_key](https://registry.terraform.io/providers/ThalesGroup/ciphertrust/latest/docs/resources/aws_xks_key) resource.
For linked HYOK (XKS) key, External Key Store needs to be in `Connected` state before creating linked HYOK (XKS) key.

It's possible to identify the key using a range of fields.


## Example Usage

```terraform
# Retrieve details using the terraform resource ID
data "ciphertrust_aws_xks_key" "by_resource_id" {
  id = ciphertrust_aws_xks_key.aws_xks_key.id
}

# Retrieve details using the CipherTrust key ID
data "ciphertrust_aws_xks_key" "by_key_id" {
  key_id = ciphertrust_aws_xks_key.aws_xks_key.key_id
}

# Retrieve details using the AWS key ARN (applicable only for linked key)
data "ciphertrust_aws_xks_key" "by_arn" {
  arn = ciphertrust_aws_xks_key.aws_xks_key.arn
}

# Retrieve details using the alias and a region (applicable only for linked key)
data "ciphertrust_aws_xks_key" "by_alias_and_region" {
  alias  = ["key_name"]
  region = "region"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `alias` (Set of String) Input parameter. Alias assigned to the the XKS key
- `arn` (String) The Amazon Resource Name (ARN) of the key.
- `description` (String) Description of the AWS key.
- `id` (String) XKS key ID.
- `key_id` (String) CipherTrust key ID. Can be used alone to identify the key, all other parameters will be ignored.
- `origin` (String) Source of the CMK's key material.  Options: AWS_CLOUDHSM, EXTERNAL_KEY_STORE.
- `region` (String) AWS region in which XKS key is created.
- `tags` (Map of String) A list of tags assigned to the XKS key.

### Read-Only

- `auto_rotate` (Boolean) True if AWS autorotation is enabled.
- `aws_account_id` (String) AWS account ID.
- `aws_custom_key_store_id` (String) Custom keystore ID in AWS.
- `aws_key_id` (String) AWS key ID.
- `aws_xks_key_id` (String) XKS key ID in AWS.
- `blocked` (Boolean) Parameter to indicate if AWS XKS key is blocked for any data plane operation.
- `cloud_name` (String) AWS cloud.
- `created_at` (String) Date the key was created.
- `custom_key_store_id` (String) Custom keystore ID in AWS.
- `customer_master_key_spec` (String) Specifies a symmetric key or an asymmetric key pair and the encryption algorithms.
- `deletion_date` (String) Date the key is scheduled for deletion.
- `enabled` (Boolean) (Updateable) True if the key is enabled.
- `encryption_algorithms` (List of String) Encryption algorithms of an asymmetric key
- `expiration_model` (String) Expiration model.
- `external_accounts` (List of String) Other AWS accounts that have access to this key.
- `key_admins` (List of String) Key administrators - users.
- `key_admins_roles` (List of String) Key administrators - roles.
- `key_manager` (String) Key manager.
- `key_material_origin` (String) Key material origin.
- `key_policy` (List of Object) (Updateable) Key policy to attach to the AWS key. Policy and key administrators, key_users, and AWS accounts are mutually exclusive. Specify either the policy or any one user at a time. If no parameters are specified, the default policy is used. (see [below for nested schema](#nestedatt--key_policy))
- `key_rotation_enabled` (Boolean) True if rotation is enabled in AWS for this key.
- `key_source` (String) Source of the key.
- `key_source_container_id` (String) ID of the source container of the key.
- `key_source_container_name` (String) Name of the source container of the key.
- `key_state` (String) Key state.
- `key_type` (String) Key type.
- `key_usage` (String) Specifies the intended use of the key. RSA key options: ENCRYPT_DECRYPT, SIGN_VERIFY. Default is ENCRYPT_DECRYPT. EC key options: SIGN_VERIFY. Default is SIGN_VERIFY. Symmetric key options: ENCRYPT_DECRYPT. Default is ENCRYPT_DECRYPT.
- `key_users` (List of String) Key users - users.
- `key_users_roles` (List of String) Key users - roles.
- `kms` (String) Kms name.
- `kms_id` (String) Kms ID
- `labels` (Map of String) A list of key:value pairs associated with the key.
- `linked` (Boolean) Parameter to indicate if AWS XKS key is linked with AWS.
- `local_hosted_params` (List of Object) Parameters for a AWS XKS key. (see [below for nested schema](#nestedatt--local_hosted_params))
- `local_key_id` (String) CipherTrust key identifier of the external key.
- `local_key_name` (String) CipherTrust key name of the external key.
- `multi_region` (Boolean) True if the key is a multi-region key.
- `policy` (String) AWS key policy.
- `policy_template_tag` (Map of String) AWS key tag for an associated policy template.
- `rotated_at` (String) Time when this key was rotated by a scheduled rotation job.
- `rotated_from` (String) CipherTrust Manager key ID from of the key this key has been rotated from by a scheduled rotation job.
- `rotated_to` (String) CipherTrust Manager key ID which this key has been rotated too by a scheduled rotation job.
- `rotation_status` (String) Rotation status of the key.
- `synced_at` (String) Date the key was synchronized.
- `updated_at` (String) Date the key was last updated.
- `valid_to` (String) Date of key material expiry.

<a id="nestedatt--key_policy"></a>
### Nested Schema for `key_policy`

Read-Only:

- `external_accounts` (List of String)
- `key_admins` (List of String)
- `key_admins_roles` (List of String)
- `key_users` (List of String)
- `key_users_roles` (List of String)
- `policy` (String)
- `policy_template` (String)


<a id="nestedatt--local_hosted_params"></a>
### Nested Schema for `local_hosted_params`

Read-Only:

- `blocked` (Boolean)
- `custom_key_store_id` (String)
- `source_key_id` (String)
- `source_key_tier` (String)

