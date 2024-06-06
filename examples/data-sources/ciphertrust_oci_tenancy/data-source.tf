# Get details of all tenancy resources
data "ciphertrust_oci_tenancy" "tenancy_datasource" {
}

# Get details of tenancy resource using tenancy OCID
data "ciphertrust_oci_tenancy" "tenancy_by_ocid" {
  tenancy_ocid = "tenancy ocid"
}

# Get details of a tenancy resource using tenancy name
data "ciphertrust_oci_tenancy" "tenancy_by_name" {
  tenancy_name = "tenancy name"
}
