# Pre-requisites for an Azure key - Azure connection, Azure vault.
# This file shows the available options and need not be valid as a whole.

# Provider settings that affect Azure keys. All are optional.
provider "ciphertrust" {
  cloud_key_manager = {
    azure = {
      # On destroy, purge a key after it is soft-deleted, if purge is supported
      # by the vault. Default is true. If false, the key is only soft-deleted.
      purge_keys_on_delete = true

      # If creating a key fails because the name belongs to a soft-deleted key,
      # recover that key instead. Default is false.
      recover_soft_deleted_keys = false

      # Keep the key's backups in CipherTrust Manager after the key is purged.
      # Default is true. If true, the key is retained in CipherTrust Manager and
      # can be restored later. If false, the backups are deleted and the key is
      # removed from CipherTrust Manager.
      retain_key_backups_after_purge = true
    }
  }
}

# Define an Azure connection
resource "ciphertrust_azure_connection" "connection" {
  name          = "azure-connection"
  client_id     = "your-client-id"
  tenant_id     = "your-tenant-id"
  client_secret = "your-client-secret"
  products      = ["cckm"]
}

# Get the subscriptions available to the connection
data "ciphertrust_azure_subscription_details" "subs" {
  connection_id = ciphertrust_azure_connection.connection.id
}

# Add an Azure vault to CipherTrust Manager
resource "ciphertrust_azure_vault" "vault" {
  name            = "my-key-vault"
  connection_id   = ciphertrust_azure_connection.connection.id
  subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
}

# Define a native RSA key
resource "ciphertrust_azure_key" "rsa_key" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = "rsa-key"
  azure_params = {
    key = {
      kty = "RSA"
      # Optional
      key_ops = ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"]
    }
    key_size = 2048
    # Optional
    attributes = {
      enabled         = true
      activation_date = "2026-07-03T14:24:00Z"
      expiration_date = "2030-07-03T14:24:00Z"
    }
    tags = {
      key-tag = "key-value"
    }
  }
}

# Define a native EC key
resource "ciphertrust_azure_key" "ec_key" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = "ec-key"
  azure_params = {
    key = {
      kty   = "EC"
      curve = "P-256"
    }
  }
}

# Define an exportable HSM key.
resource "ciphertrust_azure_key" "exportable_key" {
  # The vault must be a premium vault
  vault_id   = ciphertrust_azure_vault.vault.id
  name       = "exportable-key"
  exportable = true
  # release_policy is required when exportable is true
  release_policy = jsonencode({
    version = "1.0.0"
    anyOf = [
      {
        authority = "https://sharedweu.cae.attest.azure.net"
        allOf = [
          {
            claim  = "x-ms-attestation-type"
            equals = "sevsnpvm"
          }
        ]
      }
    ]
  })
  azure_params = {
    key = {
      kty = "RSA-HSM"
    }
    key_size = 3072
  }
}

# Scheduler and auto-backup / auto-rotation notes
# - Neither enable_auto_backup nor enable_auto_rotation can be set when a key is
#   created. Create the key first, then add the block and apply again.
# - Removing a block disables the job for the key.

# Define a key backup scheduler
resource "ciphertrust_scheduler" "scheduled_backup" {
  name      = "azure-key-backup"
  operation = "cckm_key_backup"
  run_at    = "0 9 * * fri"
  run_on    = "any"
  cckm_key_backup_params = {
    cloud_name = "AzureCloud"
  }
}

# Define a key rotation scheduler
resource "ciphertrust_scheduler" "scheduled_rotation" {
  name      = "azure-key-rotation"
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * fri"
  run_on    = "any"
  cckm_key_rotation_params = {
    cloud_name = "AzureCloud"
    expiration = "365d"
    expire_in  = "10d"
    # rotation_after = "30d"
  }
}

# After the key is created, enable the schedulers by updating the resource.
# backup_config is read-only. It holds backup_job_config_id when a backup job is enabled.
#
# key_source is the source of the key material of each new key version.
# - native: the new version is created in Azure. Supports RSA, EC, RSA-HSM and EC-HSM.
# - ciphertrust: the new version is created in CipherTrust Manager and uploaded
#   to Azure. Supports RSA only.

# Rotate with a native EC key source
resource "ciphertrust_azure_key" "scheduled_native_ec_key" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = "scheduled-native-ec-key"
  azure_params = {
    key = {
      kty   = "EC"
      curve = "P-256"
    }
  }
  enable_auto_backup = {
    job_config_id = ciphertrust_scheduler.scheduled_backup.id
  }
  enable_auto_rotation = {
    job_config_id = ciphertrust_scheduler.scheduled_rotation.id
    key_source    = "native"
    key_type      = "EC"
    # Required when key_type is EC or EC-HSM
    ec_name = "P-256"
    # Optional. Default is true.
    enable_key = true
  }
}

# Rotate with a ciphertrust RSA key source
resource "ciphertrust_azure_key" "scheduled_ciphertrust_rsa_key" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = "scheduled-ciphertrust-rsa-key"
  azure_params = {
    key = {
      kty = "RSA"
    }
    key_size = 2048
  }
  enable_auto_rotation = {
    job_config_id = ciphertrust_scheduler.scheduled_rotation.id
    key_source    = "ciphertrust"
    key_type      = "RSA"
    # Required when key_type is RSA or RSA-HSM
    key_size = 2048
  }
}

# Create a Point In Time (PIT) backup of a key. See the
# ciphertrust_azure_key_pit_backup resource.
resource "ciphertrust_azure_key_pit_backup" "backup" {
  key_id  = ciphertrust_azure_key.rsa_key.id
  trigger = "initial"
}

# Restore a key into a vault from its latest backup.
# restore_key.key_id is the CipherTrust Manager ID of the key to restore.
# No other key attributes may be set. restore_key cannot be combined with
# upload_key.
# Restoring an AVAILABLE or SOFT-DELETED key requires CipherTrust Manager 2.17
# or later and the key must be restored to a different vault.
resource "ciphertrust_azure_key" "restored_key" {
  vault_id = ciphertrust_azure_vault.vault.id
  restore_key = {
    key_id = "cipherTrust-key-id"
  }
}

# Restore a key into a vault from a specific PIT backup.
# restore_key.backup_id is optional. If it is not set, the latest backup is
# restored. Backup IDs can be listed with the
# ciphertrust_azure_key_pit_backup_list data source.
resource "ciphertrust_azure_key" "restored_key_from_backup" {
  vault_id = ciphertrust_azure_vault.vault.id
  restore_key = {
    key_id    = ciphertrust_azure_key.rsa_key.id
    backup_id = ciphertrust_azure_key_pit_backup.backup.id
  }
}

# Upload a key that exists in CipherTrust Manager to the vault.
# The azure_params kty, curve and key_size cannot be set. They are reported by
# Azure after the upload.
resource "ciphertrust_azure_key" "uploaded_local_key" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = "uploaded-local-key"
  upload_key = {
    source_key_tier = "local"
    source_key_id   = "cipherTrust-key-id"
  }
}

# Upload a key from a PFX file to the vault.
resource "ciphertrust_azure_key" "uploaded_pfx_key" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = "uploaded-pfx-key"
  upload_key = {
    source_key_tier = "pfx"
    pfx             = "/path/to/key.pfx"
    pfx_password    = "pfx-password"
  }
}

# Define a key encryption key (KEK) for uploading an HSM key. Azure requires an
# RSA-HSM key (2048, 3072 or 4096 bits) in the same premium vault, with import as
# its only key operation.
resource "ciphertrust_azure_key" "kek" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = "upload-kek"
  azure_params = {
    key = {
      kty     = "RSA-HSM"
      key_ops = ["import"]
    }
    key_size = 3072
  }
}

# Upload a key as an HSM key. The vault must be a premium or managed HSM vault.
# kek_kid is optional. It is the CipherTrust ID of the KEK. If it is omitted, CCKM
# creates a temporary KEK.
resource "ciphertrust_azure_key" "uploaded_hsm_key" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = "uploaded-hsm-key"
  upload_key = {
    source_key_tier = "local"
    source_key_id   = "cipherTrust-key-id"
    hsm             = true
    kek_kid         = ciphertrust_azure_key.kek.id
  }
}