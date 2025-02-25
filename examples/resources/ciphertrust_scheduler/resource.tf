# Specify the Terraform block to define required providers and their versions.
terraform {
  required_providers {
    ciphertrust = {
      # Define the provider source and version.
      source = "thalesgroup.com/oss/ciphertrust"
      version = "1.0.0"
    }
  }
}

# Configure the CipherTrust provider with connection details.
provider "ciphertrust" {
  # Address of the CipherTrust Manager.
  address = "https://10.10.10.10"
  # Username for authentication.
  username = "admin"
  # Password for authentication.
  password = "SamplePass@12"
  bootstrap = "no"
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
    "custom_meta_key1" = "custom_value1"  # Example custom metadata key-value pair
    "customer_meta_key2" = "custom_value2"  # Another custom metadata entry
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
