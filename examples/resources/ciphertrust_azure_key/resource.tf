# Basic create key usage

resource "ciphertrust_azure_key" "azure_key" {
  key_type = "EC"
  name     = "key_name"
  vault    = ciphertrust_azure_vault.standard_vault.id
}

# Upload a HSM key to Azure

resource "ciphertrust_azure_key" "azure_key" {
  name = "key_name"
  upload_key {
    hsm_key_id      = ciphertrust_hsm_key.hsm_key.private_key_id
    source_key_tier = "hsm-luna"
  }
  vault = ciphertrust_azure_vault.standard_vault.id
}

# Schedule key rotation using a Luna-SM as the key source

resource "ciphertrust_azure_key" "azure_key" {
  enable_rotation {
    hsm_partition_id = ciphertrust_hsm_partition.hsm_partition.id
    job_config_id    = ciphertrust_scheduler.rotation_job.id
    key_source       = "hsm-luna"
  }
  name     = "key_name"
  vault    = ciphertrust_azure_vault.standard_vault.id
}
