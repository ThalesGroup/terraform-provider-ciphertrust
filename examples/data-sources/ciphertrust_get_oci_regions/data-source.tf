
# Retrieve a list of regions available to an OCI connection
data "ciphertrust_get_oci_regions" "oci_regions" {
  connection_id = "oci_connection_name_or_id"
}
