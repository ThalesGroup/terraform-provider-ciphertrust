# Indirectly this resource is dependent on a ciphertrust_azure_connection resource
resource "ciphertrust_azure_connection" "azure_connection" {
  name = "connection-name"
}

# This resource is dependent on a ciphertrust_azure_vault resource
resource "ciphertrust_azure_vault" "azure_vault" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = "azure-subscription-id"
  name             = "azure-vault-name"
}

# Create a 2048 bit RSA Azure key
resource "ciphertrust_azure_key" "azure_key" {
  name  = "key-name"
  vault = ciphertrust_azure_vault.azure_vault.id
}

# Upload an existing CipherTrustKey to Azure
resource "ciphertrust_azure_key" "azure_key" {
  name = "key-name"
  upload_key {
    local_key_id    = ciphertrust_cm_key.cihpertrust_key.id
    source_key_tier = "local"
  }
  vault = ciphertrust_azure_vault.azure_vault.id
}

# Upload an existing Luna-HSM key to Azure
resource "ciphertrust_azure_key" "azure_key" {
  name = "key-name"
  upload_key {
    hsm_key_id      = ciphertrust_hsm_key.hsm_key.private_key_id
    source_key_tier = "hsm-luna"
  }
  vault = ciphertrust_azure_vault.azure_vault.id
}

# Upload an existing Luna-HSM key to Azure as an exportable key
resource "ciphertrust_azure_key" "azure_key" {
  name = "key-name"
  upload_key {
    hsm_key_id      = ciphertrust_hsm_key.hsm_key.private_key_id
    source_key_tier = "hsm-luna"
    exportable      = true
    release_policy  = <<-EOT
    {
      "anyOf": [{
        "anyOf": [{
          "claim": "lzxdwiqk24k24",
          "equals": "true"
        }],
        "authority": "https://lzxdwiqk24jkh.ncus.attest.azure.net"
      }],
      "version": "1.0.0"
    }
    EOT
  }
  vault = ciphertrust_azure_vault.azure_vault.id
}

# Upload an existing DSM key to Azure
resource "ciphertrust_azure_key" "azure_key" {
  name = "key-name"
  upload_key {
    dsm_key_id      = ciphertrust_dsm_key.dsm_key.id
    source_key_tier = "dsm"
  }
  vault = ciphertrust_azure_vault.azure_vault.id
}

# Upload a PFX file to Azure
resource "ciphertrust_azure_key" "azure_key" {
  name = "key-name"
  upload_key {
    pfx             = "path-to-pfx-file"
    pfx_password    = "pfx-password"
    source_key_tier = "pfx"
  }
  vault = ciphertrust_azure_vault.azure_vault.id
}

# A scheduler resource suitable for the rotation of Azure keys
resource "ciphertrust_scheduler" "azure_scheduled_key_rotation" {
  cckm_key_rotation_params {
    cloud_name = "AzureCloud"
  }
  name       = "rotation-job-name"
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
}

# Schedule key rotation using Azure as the key source
resource "ciphertrust_azure_key" "azure_key" {
  enable_rotation {
    job_config_id = ciphertrust_scheduler.azure_scheduled_key_rotation.id
    key_source    = "native"
  }
  name  = "key-name"
  vault = ciphertrust_azure_vault.azure_vault.id
}

# Schedule key rotation using CipherTrust Manager as the key source
resource "ciphertrust_azure_key" "azure_key" {
  enable_rotation {
    job_config_id = ciphertrust_scheduler.azure_scheduled_key_rotation.id
    key_source    = "ciphertrust"
  }
  name  = "key-name"
  vault = ciphertrust_azure_vault.azure_vault.id
}

# Schedule key rotation using a Luna-HSM as the key source
resource "ciphertrust_azure_key" "azure_key" {
  enable_rotation {
    hsm_partition_id = ciphertrust_hsm_partition.hsm_partition.id
    job_config_id    = ciphertrust_scheduler.azure_scheduled_key_rotation.id
    key_source       = "hsm-luna"
  }
  name  = "key-name"
  vault = ciphertrust_azure_vault.azure_vault.id
}

# Schedule key rotation using a DSM as the key source
resource "ciphertrust_azure_key" "azure_key" {
  enable_rotation {
    dsm_domain_id = ciphertrust_dsm_domain.dsm_domain.id
    job_config_id = ciphertrust_scheduler.azure_scheduled_key_rotation.id
    key_source    = "dsm"
  }
  name  = "key-name"
  vault = ciphertrust_azure_vault.azure_vault.id
}

# Restore an Azure key to another vault
resource "ciphertrust_azure_key" "restored_key" {
  restore_key_id = ciphertrust_azure_key.azure_key.key_id
  vault          = ciphertrust_azure_vault.azure_vault.id
}

# Restore an Azure key to another vault and enable it for rotation
resource "ciphertrust_azure_key" "restored_key" {
  restore_key_id = ciphertrust_azure_key.azure_key.key_id
  vault          = ciphertrust_azure_vault.azure_vault.id
  enable_rotation {
    job_config_id = ciphertrust_scheduler.azure_scheduled_key_rotation.id
    key_source    = "ciphertrust"
  }
}
