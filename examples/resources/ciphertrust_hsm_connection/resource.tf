resource "ciphertrust_hsm_connection" "hsm_connection" {
  is_ha_enabled = true
  hostname    = "10.123.45.67"
  server_id   = ciphertrust_hsm_server.hsm_server.id
  name        = "hsm_connection_name"
  partitions {
      partition_label = "partition_label_one"
      serial_number   = "serial_number_one"
  }
  partitions {
     partition_label = "partition_label_two"
     serial_number   = "serial_number_two"
  }
  partition_password = "hsm_partition_password"
}
