# Retrieve a list of vaults available to an OCI connection in the given compartment and region
data "ciphertrust_get_oci_vaults" "oci_vaults" {
  connection_id  = "oci_connection_name_or_id"
  region         = "oci_region"
  compartment_id = "compartment_ocid"
}
