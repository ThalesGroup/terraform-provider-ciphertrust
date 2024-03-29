---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_virtual_key Resource - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_virtual_key (Resource)

- Primary uses of the ciphertrust_virtual_key resource is to create an AWS HYOK key with luna as key source in custom key store of type EXTERNAL_KEY_STORE.  
- Virtual key by default is non-deletable (can be updated to deletable)
- Virtual key is linked to a key in Luna HSM.  
- Luna key should have following attributes to create a virtual key:  
  - CKA_EXTRACTABLE = FALSE
  - CKA_ENCRYPT = TRUE
  - CKA_DECRYPT = TRUE
  - CKA_WRAP = TRUE
  - CKA_UNWRAP = TRUE
  - hyok_key   = TRUE
- Virtual key resource depends on following resources:
  - [ciphertrust_hsm_key](https://registry.terraform.io/providers/ThalesGroup/ciphertrust/latest/docs/resources/hsm_key) resource for Luna as key source.

This resource is applicable to CipherTrust Manager only.

## Example Usage

```terraform
# Create Luna Connection, Luna HSM server, Luna Symmetric key and virtual key for Luna as key source
# Create a hsm network server
resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = "hsm-ip"
  hsm_certificate = "/path/to/hsm_server_cert.pem"
}

# Create a Luna hsm connection
# is_ha_enabled must be true for more than one partition
resource "ciphertrust_hsm_connection" "hsm_connection" {
  depends_on = [
    ciphertrust_hsm_server.hsm_server,
  ]
  hostname  = "hsm-ip"
  server_id = ciphertrust_hsm_server.hsm_server.id
  name      = "luna-hsm-connection"
  partitions {
    partition_label = "partition-label"
    serial_number   = "serial-number"
  }
  partition_password = "partition-password"
  is_ha_enabled      = false
}
output "hsm_connection_id" {
  value = ciphertrust_hsm_connection.hsm_connection.id
}

# Add a partition to connection
resource "ciphertrust_hsm_partition" "hsm_partition" {
  depends_on = [
    ciphertrust_hsm_connection.hsm_connection,
  ]
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
}
output "hsm_partition" {
  value = ciphertrust_hsm_partition.hsm_partition
}

# Create an Symmetric AES-256 Luna HSM key for creating EXTERNAL_KEY_STORE with Luna as key source
resource "ciphertrust_hsm_key" "hsm_aes_key" {
  depends_on = [
    ciphertrust_hsm_partition.hsm_partition,
  ]
  attributes = ["CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP", "CKA_UNWRAP"]
  label        = "key-name"
  mechanism    = "CKM_AES_KEY_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
  key_size     = 256
  hyok_key     = true
}

output "hsm_aes_key" {
  value = ciphertrust_hsm_key.hsm_aes_key
}

# Create a virtual key from above luna key
resource "ciphertrust_virtual_key" "virtual_key_from_luna_key" {
  depends_on = [
    ciphertrust_hsm_key.hsm_aes_key,
  ]
  deletable = false
  source_key_id = ciphertrust_hsm_key.hsm_aes_key.id
  source_key_tier = "hsm-luna"
}
output "virtual_key_from_luna_key" {
  value = ciphertrust_virtual_key.virtual_key_from_luna_key
}
```
<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `deletable` (Boolean) False during create and updateable to delete indicating virtual key to be deletable.
- `source_key_id` (String) HSM key ID
- `source_key_tier` (String) Source key tier for virtual key - hsm-luna or local.

### Read-Only

- `created_at` (String) Date the virtual key was created.
- `id` (String) Virtual Key ID.
- `name` (String) Unique name for the virtual key.
- `partition_id` (String) Partition ID for referenced luna source key.
- `partition_label` (String) Partition label for referenced luna source key.
- `updated_at` (String) Date the virtual key was last updated.
- `version` (Number) Version number of the virtual key.


