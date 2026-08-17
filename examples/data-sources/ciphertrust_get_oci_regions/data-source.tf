# Retrieve OCI regions available to a connection.
data "ciphertrust_get_oci_regions" "regions" {
  connection_id = "oci-prod-connection"
}
