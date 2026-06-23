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
    backup_key  = "d370535b-a035-4251-9780-e608f713be77"
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
