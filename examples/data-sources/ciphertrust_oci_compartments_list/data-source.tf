# Sort compartments by creation date, newest first.
data "ciphertrust_oci_compartments_list" "sorted" {
  filters = {
    sort = "-createdAt"
  }
}

# List compartments by tenancy and name.
data "ciphertrust_oci_compartments_list" "by_tenancy_and_name" {
  filters = {
    tenancy = "my-tenancy"
    name    = "prod-compartment"
  }
}
