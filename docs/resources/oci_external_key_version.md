---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_oci_external_key_version Resource - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_oci_external_key_version (Resource)

OCI key versions can be added to [ciphertrust_oci_external_key](https://registry.terraform.io/providers/ThalesGroup/ciphertrust/latest/docs/resources/oci_external_key) resources.

Key versions may be created from the following key sources:
- CipherTrust Manager Key [ciphertrust_cm_key](https://registry.terraform.io/providers/ThalesGroup/ciphertrust/latest/docs/resources/cm_key)
- Luna-HSM Key [ciphertrust_hsm_key](https://registry.terraform.io/providers/ThalesGroup/ciphertrust/latest/docs/resources/hsm_key)

It's not possible for key versions to be added to the same key from different key sources.

### Importing a Key Version into Terraform State

Use the following steps to import the version that is created when the key is created into terraform state.

1. Add a ciphertrust_oci_external_key_version resource to the script specifying the required options. For example:

```terraform
        resource "ciphertrust_oci_external_key_version" "imported_version" {
          key_id          = "Resource ID of the OCI external key, eg: ciphertrust_oci_external_key.my_key.id"
          source_key_id   = "Resource ID of the source key, eg: ciphertrust_oci_external_key.my_key.source_key_id"
          source_key_tier = "Specify local or hsm-luna, eg: ciphertrust_oci_external_key.my_key.source_key_tier"
        }
```
2. Run the import command.
 
        The import command will be in the form of:
            terraform import ciphertrust_oci_external_key_version.<version resource name> <ciphertrust key id>:<ciphertrust version id>
        For example:
            terraform import ciphertrust_oci_external_key_version.imported_version e1af516e-f909-4f6c-bce5-f0f54009e587:b92d102b-d8b6-424e-a776-f1e54d6bb9a2

    An example of successful output is:
```terraform
        ciphertrust_oci_external_key_version.imported_version: Importing from ID "29338e84-cf17-4c2c-8f6b-3c15595ca351:be2f16c1-570a-494d-9d9d-b98d644828be"...
        ciphertrust_oci_external_key_version.imported_version: Import prepared!
          Prepared ciphertrust_oci_external_key_version for import
        ciphertrust_oci_external_key_version.imported_version: Refreshing state... [id=be2f16c1-570a-494d-9d9d-b98d644828be]

        Import successful!

        The resources that were imported are shown above. These resources are now in your Terraform state and will henceforth be managed by Terraform.
```

## Example Usage

```terraform
# Create a tenancy resource
resource "ciphertrust_oci_tenancy" "oci_tenancy" {
  tenancy_ocid = "tenancy-ocid"
  tenancy_name = "tenancy-name"
}

# Create an OCI issuer resource
resource "ciphertrust_oci_issuer" "oci_issuer" {
  name              = "issuer-name"
  openid_config_url = "open-config-url"
}

# Create an OCI external vault that will accept both CipherTrust and Hsm-Luna keys
resource "ciphertrust_oci_external_vault" "external_vault" {
  client_application_id = "oci-client-application-id"
  issuer_id             = ciphertrust_oci_issuer.oci_issuer.id
  tenancy_id            = ciphertrust_oci_tenancy.oci_tenancy.id
  vault_name            = "vault-name"
}

# Create a CipherTrust key that can be added to the vault
resource "ciphertrust_cm_key" "ciphertrust_key" {
  name         = "key-name"
  algorithm    = "AES"
  undeletable  = true
  unexportable = true
}

# Add the key to the vault
resource "ciphertrust_oci_external_key" "external_key" {
  cckm_vault_id = ciphertrust_oci_external_vault.external_vault.id
  name          = "key-name"
  source_key_id = ciphertrust_cm_key.ciphertrust_key.id
}

# Create another CipherTrust key that can be added to the vault
resource "ciphertrust_cm_key" "key_version" {
  name         = "key-name"
  algorithm    = "AES"
  undeletable  = true
  unexportable = true
}

# Add it as a version of the key
resource "ciphertrust_oci_external_key_version" "key_version" {
  key_id          = ciphertrust_oci_external_key.external_key.id
  source_key_id   = ciphertrust_cm_key.key_version.id
  source_key_tier = "local"
}

# Create a ciphertrust_hsm_server resource
resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = "hsm-ip"
  hsm_certificate = "hsm-server.pem"
}

# Create a ciphertrust_hsm_connection resource
resource "ciphertrust_hsm_connection" "hsm_connection" {
  is_ha_enabled = true
  hostname    = "hsm-ip"
  server_id   = ciphertrust_hsm_server.hsm_server.id
  name        = "connection-name"
  partitions {
    partition_label = "partition-label"
    serial_number   = "serial-number"
  }
  partition_password = "partition-password"
}

# Create a ciphertrust_hsm_partition resource
resource "ciphertrust_hsm_partition" "hsm_partition" {
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
}

# Create a hsm-luna key that is able to be utilized by the external vault
resource "ciphertrust_hsm_key" "hsm_luna_key" {
  hyok_key     = true
  key_size     = 256
  label        = "key-name"
  mechanism    = "CKM_AES_KEY_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
}

# Add the hsm-luna key to the vault
resource "ciphertrust_oci_external_key" "hsm_luna_external_key" {
  cckm_vault_id   = ciphertrust_oci_external_vault.external_vault.id
  name            = "key-name"
  source_key_id   = ciphertrust_hsm_key.hsm_luna_key.id
  source_key_tier = "hsm-luna"
}

# Create another hsm-luna key
resource "ciphertrust_hsm_key" "hsm_luna_key_version" {
  hyok_key     = true
  key_size     = 256
  label        = "key-name"
  mechanism    = "CKM_AES_KEY_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
}

# Add it as a version of the key
resource "ciphertrust_oci_external_key_version" "key_version_luna" {
  key_id          = ciphertrust_oci_external_key.hsm_luna_external_key.id
  source_key_id   = ciphertrust_hsm_key.hsm_luna_key_version.id
  source_key_tier = "hsm-luna"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `cckm_key_id` (String) CipherTrust Manager Key ID.
- `source_key_id` (String) Source key ID.

### Optional

- `source_key_tier` (String) Source of the key. Options: local, hsm-luna. Default is local.

### Read-Only

- `cloud_name` (String) oci.
- `created_at` (String) Date and time the key version was created.
- `id` (String) CipherTrust version identifier.
- `key_material_origin` (String) Key material origin of the version.
- `oci_key_id` (String) OCI key ID.
- `partition_id` (String) Luna-HSM Partition ID.
- `partition_label` (String) Luna-HSM Partition Label.
- `source_key_name` (String) Source key name.
- `state` (String) State of the key version.
- `updated_at` (String) Date and time of last update.