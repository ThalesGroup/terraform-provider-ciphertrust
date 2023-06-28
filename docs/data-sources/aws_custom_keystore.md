---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_aws_custom_keystore Data Source - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_aws_custom_keystore (Data Source)

This data-source retrieves details of a [ciphertrust_aws_custom_keystore](https://registry.terraform.io/providers/ThalesGroup/ciphertrust/latest/docs/resources/aws_custom_keystore) resource.

It's possible to identify the key store using `id` field.

## Example Usage

```terraform
# Retrieve details using the terraform resource ID
data "ciphertrust_aws_custom_keystore" "by_resource_id" {
  id = ciphertrust_aws_custom_keystore.custom_keystore.id
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `id` (String) Custom keystore ID.

### Read-Only

- `access_key_id` (String) Access key id of credential of AWS custom keystore of type EXTERNAL_KEYSTORE.
- `aws_param` (List of Object) Parameters related to AWS interaction with a custom key store. (see [below for nested schema](#nestedatt--aws_param))
- `cloud_name` (String) Name of the cloud.
- `connect_disconnect_keystore` (String) Desired state of custom keystore - CONNECT_KEYSTORE, DISCONNECT_KEYSTORE.
- `created_at` (String) Date the custom keystore was created.
- `credential_version` (Number) Credential Version of the AWS custom keystore.
- `kms` (String) Name or id for the KMS in which custom keystore belongs.
- `kms_id` (String) ID for the KMS in which custom keystore belongs.
- `linked_state` (Boolean) Parameter to indicate if custom keystore is linked with AWS.
- `local_hosted_params` (List of Object) Parameters for a custom key store that is locally hosted. (see [below for nested schema](#nestedatt--local_hosted_params))
- `name` (String) (Updateable) Unique name for the custom keystore.
- `region` (String) Region of the AWS custom keystore.
- `secret_access_key` (String) Secret access key of credential of AWS custom keystore of type EXTERNAL_KEYSTORE.
- `type` (String) Location of the AWS custom keystore - LOCAL, REMOTE, CloudHSM.
- `updated_at` (String) Date the custom keystore was last updated.

<a id="nestedatt--aws_param"></a>
### Nested Schema for `aws_param`

Read-Only:

- `cloud_hsm_cluster_id` (String)
- `connection_state` (String)
- `custom_key_store_id` (String)
- `custom_key_store_name` (String)
- `custom_key_store_type` (String)
- `key_store_password` (String)
- `trust_anchor_certificate` (String)
- `xks_proxy_connectivity` (String)
- `xks_proxy_uri_endpoint` (String)
- `xks_proxy_uri_path` (String)
- `xks_proxy_vpc_endpoint_service_name` (String)


<a id="nestedatt--local_hosted_params"></a>
### Nested Schema for `local_hosted_params`

Read-Only:

- `blocked` (Boolean)
- `health_check_ciphertext` (String)
- `health_check_key_id` (String)
- `linked_state` (Boolean)
- `max_credentials` (Number)
- `partition_id` (String)
- `partition_label` (String)
- `source_container_id` (String)
- `source_container_type` (String)
- `source_key_tier` (String)

