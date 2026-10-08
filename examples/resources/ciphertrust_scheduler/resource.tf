# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of CipherTrust scheduler
# resources for the different supported scheduled job operations.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.1"
    }
  }
}

# Configure the CipherTrust provider for authentication
provider "ciphertrust" {
  # The address of the CipherTrust appliance (replace with the actual address)
  address = "https://10.10.10.10"

  # Username for authenticating with the CipherTrust appliance
  username = "admin"

  # Password for authenticating with the CipherTrust appliance
  password = "ChangeMe101!"
}

# Define an SCP connection resource with CipherTrust
resource "ciphertrust_scp_connection" "scp_connection" {
  name = "scp-connection"
  products = [
    "backup/restore"
  ]
  description = "a description of the connection"
  host        = "10.10.10.10"
  port        = 22
  username    = "user"
  auth_method = "Password"
  password    = "password"
  path_to     = "/home/path/to/directory/"
  protocol    = "sftp"
  public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNxnOBfBVU4L3fQBVWK71CdoHXmFNxkD0lFYDagM8etytGxRMQeOSeARUYQA+xC/8ig+LHimQ97L0XPSCvTr/XbXxOYBOdGHFqr1o6QwmSBABoPz0fvfCHaipAdwGlfS50aDbCWYZSd9UX6stOazCPdQ9wiiGD0+wYmagxBtrBlzrXiXKV3q+GNr6iIlejsv2aK"
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1"   = "custom_value1"
    "customer_meta_key2" = "custom_value2"
  }
}

# Database backup scheduler
resource "ciphertrust_scheduler" "scheduler" {
  name        = "db_backup1-terraform"
  operation   = "database_backup"
  description = "This is to backup db"
  run_on      = "any"
  run_at      = "*/15 * * * *"

  database_backup_params = {
    # backup_key defaults to CM's default backup key if omitted
    connection  = ciphertrust_scp_connection.scp_connection.id
    description = "sample description"
    do_scp      = true
    scope       = "system"
    tied_to_hsm = false
  }
}

output "scheduler" {
  value = ciphertrust_scheduler.scheduler
}

# Cloud key synchronization notes
# - Unless synchronize_all is true, the cloud container list for the cloud
#   (kms, oci_vaults or key_vaults) must contain at least one resource ID.

# AWS scheduled key rotation
resource "ciphertrust_scheduler" "aws_scheduled_rotation_job" {
  end_date = "2030-12-07T14:24:00Z"
  cckm_key_rotation_params = {
    cloud_name       = "aws"
    aws_retain_alias = true
    rotation_after   = "6d"
    rotate_material  = true
  }
  name       = "aws-scheduled-rotation"
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
  run_on     = "any"
  start_date = "2026-01-01T14:24:00Z"
}

# XKS credential rotation
resource "ciphertrust_scheduler" "xks_credential_rotation" {
  cckm_xks_credential_rotation_params = {
    cloud_name = "aws"
  }
  name      = "aws-xks-credential-rotation"
  operation = "cckm_xks_credential_rotation"
  run_at    = "0 9 * * fri"
}

# AWS synchronization of the keys of specific KMS resources
resource "ciphertrust_scheduler" "aws_sync_kms" {
  name      = "aws-sync-kms"
  operation = "cckm_synchronization"
  run_at    = "0 9 * * fri"
  cckm_synchronization_params = {
    cloud_name = "aws"
    kms        = ["kms-resource-id"]
  }
}

# AWS synchronization of all keys
resource "ciphertrust_scheduler" "aws_sync_all" {
  name      = "aws-sync-all"
  operation = "cckm_synchronization"
  run_at    = "0 9 * * sat"
  cckm_synchronization_params = {
    cloud_name      = "aws"
    synchronize_all = true
  }
}

# Azure scheduled key backup
resource "ciphertrust_scheduler" "azure_key_backup" {
  cckm_key_backup_params = {
    cloud_name = "AzureCloud"
  }
  name      = "azure-key-backup"
  operation = "cckm_key_backup"
  run_at    = "0 9 * * fri"
}

# Azure synchronization of the keys of specific key vaults
resource "ciphertrust_scheduler" "azure_sync_vaults" {
  name      = "azure-sync-vaults"
  operation = "cckm_synchronization"
  run_at    = "0 9 * * fri"
  cckm_synchronization_params = {
    cloud_name = "AzureCloud"
    key_vaults = [ciphertrust_azure_vault.vault.id]
    # sync_items currently accepts only "key"
    sync_items = ["key"]
    # Optional. Take a backup of the keys in the cloud during synchronization.
    take_cloud_key_backup = true
  }
}

# Azure synchronization of all keys
resource "ciphertrust_scheduler" "azure_sync_all" {
  name      = "azure-sync-all"
  operation = "cckm_synchronization"
  run_at    = "0 9 * * sat"
  cckm_synchronization_params = {
    cloud_name      = "AzureCloud"
    synchronize_all = true
  }
}

# OCI scheduled key rotation
resource "ciphertrust_scheduler" "oci" {
  cckm_key_rotation_params = {
    cloud_name = "oci"
    expiration = "365d"
    expire_in  = "10d"
  }
  name      = "oci-key-rotation"
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * fri"
}

# OCI synchronization of the keys of specific vaults
resource "ciphertrust_scheduler" "oci_sync_vaults" {
  name      = "oci-sync-vaults"
  operation = "cckm_synchronization"
  run_at    = "0 9 * * fri"
  cckm_synchronization_params = {
    cloud_name = "oci"
    oci_vaults = ["oci-vault-resource-id"]
  }
}

# OCI synchronization of all keys
resource "ciphertrust_scheduler" "oci_sync_all" {
  name      = "oci-sync-all"
  operation = "cckm_synchronization"
  run_at    = "0 9 * * sat"
  cckm_synchronization_params = {
    cloud_name      = "oci"
    synchronize_all = true
  }
}
