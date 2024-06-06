# Get a list of OCI regions available to the connection using the connection ID
data "ciphertrust_oci_regions" "oci_regions_by_connection_id" {
  connection_id = "oci connection id"
}

# Get a list of OCI regions available to the connection using the connection name
data "ciphertrust_oci_regions" "oci_regions_by_connection_name" {
  connection_id = "oci connection name"
}
