# Get OCI connection details using the connection name
data "ciphertrust_oci_connection" "by_name" {
  name       = "connection name"
}

# Get OCI connection details using the connection ID
data "ciphertrust_oci_connection" "by_id" {
  connection_id = "connection id"
}
