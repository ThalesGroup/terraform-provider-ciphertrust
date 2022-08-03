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

# Create a Luna-HSM key
resource "ciphertrust_hsm_key" "hsm_key" {
  attributes   = ["CKA_ENCRYPT", "CKA_DECRYPT"]
  label        = "key-name"
  mechanism    = "CKM_RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
  key_size     = 2048
}

