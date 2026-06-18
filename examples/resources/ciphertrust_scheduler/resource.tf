# Specify the Terraform block to define required providers and their versions.
terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.0-pre3"
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
  # Name of the SCP connection (unique identifier)
  name = "scp-connection"

  # List of products associated with this SCP connection
  # In this case, it's related to backup/restore operations
  products = [
    "backup/restore"
  ]

  # Description of the SCP connection
  description = "a description of the connection"

  # Host IP address or domain of the SCP server
  host = "10.10.10.10"

  # Port used for SCP communication (default SCP port is 22)
  port = 22

  # Username for authentication on the SCP server
  username = "user"

  # Authentication method to be used, here it's set to "Password"
  auth_method = "Password"

  # Password for the SCP server authentication
  password = "password"

  # Path on the remote server to store or retrieve files
  path_to = "/home/path/to/directory/"

  # Protocol used for SCP connection (can be sftp, scp, etc.)
  protocol = "sftp"

  # Public SSH key for authentication, if using key-based authentication
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNxnOBfBVU4L3fQBVWK71CdoHXmFNxkD0lFYDagM8etytGxRMQeOSeARUYQA+xC/8ig+LHimQ97L0XPSCvTr/XbXxOYBOdGHFqr1o6QwmSBABoPz0fvfCHaipAdwGlfS50aDbCWYZSd9UX6stOazCPdQ9wiiGD0+wYmagxBtrBlzrXiXKV3q+GNr6iIlejsv2aK"

  # Labels for categorizing the SCP connection
  labels = {
    "environment" = "devenv"
  }

  # Custom metadata for the SCP connection
  # This can be used to store additional information related to the SCP connection
  meta = {
    "custom_meta_key1"   = "custom_value1" # Example custom metadata key-value pair
    "customer_meta_key2" = "custom_value2" # Another custom metadata entry
  }
}


# Define a resource block to configure a scheduler in CipherTrust.
resource "ciphertrust_scheduler" "scheduler" {
  # Name of the scheduler.
  name = "db_backup1-terraform"
  # Type of operation the scheduler will perform.
  operation = "database_backup"
  # Description of the scheduler.
  description = "This is to backup db updated cancelleed"
  # Specify when the scheduler should run (e.g., "any" for no specific conditions).
  run_on = "any"
  # Cron-style schedule specifying when the job should run. Refer to the schema description to know more about the cron-style
  run_at = "*/15 * * * *"

  # Configuration for the database backup parameters.
  database_backup_params = {
    # Backup ID for the database backup.
    backup_key = "d370535b-a035-4251-9780-e608f713be77"
    # SCP Connection ID for the backup operation.
    connection = ciphertrust_scp_connection.scp_connection.id
    # Description of the backup job.
    description = "sample description"
    # Indicates if SCP should be used for the backup (true in this case).
    do_scp = true
    # Scope of the backup (e.g., "system","domain").
    scope = "system"
    # Indicates if the backup is tied to an HSM (false in this case).
    tied_to_hsm = false
  }
}

# Output block to display details of the created scheduler resource.
output "scheduler" {
  # Outputs all attributes of the scheduler resource.
  value = ciphertrust_scheduler.scheduler
}

# AWS Scheduled Key Rotation
resource "ciphertrust_scheduler" "aws_scheduled_rotation_job" {
  end_date = "2030-12-07T14:24:00Z"
  cckm_key_rotation_params {
    cloud_name       = "aws"
    aws_retain_alias = true # Apply "gravestone alias" to the "rotated-from" key"
    rotation_after   = "6d" # Number of days after which the keys will be rotated
    rotate_material  = true # Rotate key material during the key rotation job
  }
  name       = "aws-scheduled-rotation"
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
  run_on     = "any"
  start_date = "20226-01-01T14:24:00Z"
}

# XKS Credential Rotation
resource "ciphertrust_scheduler" "xks_credential_rotation" {
  cckm_xks_credential_rotation_params = {
    cloud_name = "aws"
  }
  name      = "aws-xks-credential-roration"
  operation = "cckm_xks_credential_rotation"
  run_at    = "0 9 * * fri"
}

#  OCI Scheduled Key Rotation
resource "ciphertrust_scheduler" "oci" {
  cckm_key_rotation_params {
    cloud_name = "oci"
    expiration = "365d" # Expiration time of the new key
    expire_in  = "10d"  # Rotate keys expiring in this period
  }
  name      = "oci-key-rotation"
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * fri"
}
