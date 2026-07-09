data "ciphertrust_get_oci_buckets" "buckets" {
  # Required parameters
  connection_id  = "oci-connection-id-or-name"
  compartment_id = "compartment-ocid"
  # Optional parameters
  limit          = 5
}
