# Create Luna Connection, Luna HSM server, Luna Symmetric key and virtual key for Luna as key source
# Create a hsm network server
resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = "hsm-ip"
  hsm_certificate = "/path/to/hsm_server_cert.pem"
}

# Create a Luna hsm connection
# is_ha_enabled must be true for more than one partition
resource "ciphertrust_hsm_connection" "hsm_connection" {
  depends_on = [
    ciphertrust_hsm_server.hsm_server,
  ]
  hostname  = "hsm-ip"
  server_id = ciphertrust_hsm_server.hsm_server.id
  name      = "luna-hsm-connection"
  partitions {
    partition_label = "partition-label"
    serial_number   = "serial-number"
  }
  partition_password = "partition-password"
  is_ha_enabled      = false
}
output "hsm_connection_id" {
  value = ciphertrust_hsm_connection.hsm_connection.id
}

# Add a partition to connection
resource "ciphertrust_hsm_partition" "hsm_partition" {
  depends_on = [
    ciphertrust_hsm_connection.hsm_connection,
  ]
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
}
output "hsm_partition" {
  value = ciphertrust_hsm_partition.hsm_partition
}

# Create an Symmetric AES-256 Luna HSM key for creating EXTERNAL_KEY_STORE with Luna as key source
resource "ciphertrust_hsm_key" "hsm_aes_key" {
  depends_on = [
    ciphertrust_hsm_partition.hsm_partition,
  ]
  attributes = ["CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP", "CKA_UNWRAP"]
  label        = "key-name"
  mechanism    = "CKM_AES_KEY_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
  key_size     = 256
  hyok_key     = true
}

output "hsm_aes_key" {
  value = ciphertrust_hsm_key.hsm_aes_key
}

# Create a virtual key from above luna key
resource "ciphertrust_virtual_key" "virtual_key_from_luna_key" {
  depends_on = [
    ciphertrust_hsm_key.hsm_aes_key,
  ]
  deletable = false
  source_key_id = ciphertrust_hsm_key.hsm_aes_key.id
  source_key_tier = "hsm-luna"
}
output "virtual_key_from_luna_key" {
  value = ciphertrust_virtual_key.virtual_key_from_luna_key
}
