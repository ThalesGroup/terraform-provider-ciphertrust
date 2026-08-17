# Retrieve OCI object storage buckets in a compartment.
data "ciphertrust_get_oci_buckets" "buckets" {
  connection_id  = "oci-prod-connection"
  compartment_id = "ocid1.compartment.oc1..example"
}
