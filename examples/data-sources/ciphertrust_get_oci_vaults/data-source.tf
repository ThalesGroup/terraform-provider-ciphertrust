# Retrieve OCI vaults in a compartment and region.
data "ciphertrust_get_oci_vaults" "vaults" {
  connection_id  = "oci-prod-connection"
  compartment_id = "ocid1.compartment.oc1..example"
  region         = "us-ashburn-1"
}
