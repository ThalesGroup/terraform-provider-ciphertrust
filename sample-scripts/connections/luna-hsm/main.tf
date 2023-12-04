terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.4-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "hsm-connection-${lower(random_id.random.hex)}"
}

# Create a hsm network server
resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = var.hsm_hostname
  hsm_certificate = var.hsm_certificate
}

# Add create a hsm connection
# is_ha_enabled must be true for more than one partition
resource "ciphertrust_hsm_connection" "hsm_connection" {
  hostname  = var.hsm_hostname
  server_id = ciphertrust_hsm_server.hsm_server.id
  name      = local.connection_name
  partitions {
    partition_label = var.hsm_partition_label
    serial_number   = var.hsm_partition_serial_number
  }
  partition_password = var.hsm_partition_password
  is_ha_enabled      = false
}
output "hsm_connection_id" {
  value = ciphertrust_hsm_connection.hsm_connection.id
}

# Add a partition to connection
resource "ciphertrust_hsm_partition" "hsm_partition" {
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
}
output "hsm_partition" {
  value = ciphertrust_hsm_partition.hsm_partition
}
