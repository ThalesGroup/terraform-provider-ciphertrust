data "ciphertrust_get_oci_compartments" "connection_compartments" {
  # Required parameters
  connection_id = "oci-connection-id-or-name"
  # Optional parameters
  limit         = 5
}
