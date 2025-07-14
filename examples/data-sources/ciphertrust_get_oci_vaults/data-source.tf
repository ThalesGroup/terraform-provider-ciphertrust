data "ciphertrust_get_oci_vaults" "connection_vaults" {
  # Required parameters
  connection_id  = "oci-connection-id-or-name"
  region         = "oci-region"
  compartment_id = "compartment-ocid"
  # Optional parameters
  limit          = 5
}
