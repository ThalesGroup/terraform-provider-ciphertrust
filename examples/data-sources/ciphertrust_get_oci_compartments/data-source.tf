# Retrieve OCI compartments available to a connection.
data "ciphertrust_get_oci_compartments" "compartments" {
  connection_id = "oci-prod-connection"
}
