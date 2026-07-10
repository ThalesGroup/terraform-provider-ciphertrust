data "ciphertrust_oci_compartments_list" "all" {}

data "ciphertrust_oci_compartments_list" "by_name" {
  # Optional filters: id, name, compartment_id, tenancy
  filters = {
    name = "my-compartment"
  }
}
