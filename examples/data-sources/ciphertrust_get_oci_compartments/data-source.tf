
# Retrieve a list of compartments available to an OCI connection
data "ciphertrust_get_oci_compartments" "oci_compartments" {
  connection_id = "oci_connection_name_or_id"
  limit = 5
}
