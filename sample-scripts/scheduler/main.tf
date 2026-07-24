terraform {
  required_providers {
    ciphertrust = {
      source = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {
	address = "https://10.10.10.10"
	username = "admin"
	password = "ChangeMe101!"
}

resource "ciphertrust_scp_connection" "scp_connection" {
  name = "scp-test-connection-terraform"
  products = [
    "backup/restore"
  ]
  description = "a description of the connection updated"
  host = "10.10.10.10"
  port = 22
  username = "user-updated"
  auth_method = "Password"
  password = "password"
  path_to = "/home/path/to/directory/updated"
  protocol = "sftp"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNxnOBfBVU4L3fQBVWK71CdoHXmFNxkD0lFYDagM8etytGxRMQeOSeARUYQA+xC/8ig+LHimQ97L0XPSCvTr/XbXxOYBOdGHFqr1o6QwmSBABoPz0fvfCHaipAdwGlfS50aDbCWYZSd9UX6stOazCPdQ9wiiGD0+wYmagxBtrBlzrXiXKV3q+GNr6iIlejsv2aK"
  labels = {
    "environment" = "envalue"
  }
  meta = {
    "custom_meta_key1" = "custom_value1"
    "customer_meta_key2" = "custom_value2"
  }
}


resource "ciphertrust_scheduler" "scheduler" {
  name = "db_backup1-terraform"
  operation = "database_backup"
  description = "This is to backup db updated cancelleed"
  run_on = "any"
  run_at = "*/15 * * * *"
  database_backup_params = {
    backup_key = "d370535b-a035-4251-9780-e608f713be77"
    connection = ciphertrust_scp_connection.scp_connection.id
    description = "sample des updated"
    do_scp = false
    scope = "system"
    tied_to_hsm = false
  }
}

output "scheduler" {
  value = ciphertrust_scheduler.scheduler
}
