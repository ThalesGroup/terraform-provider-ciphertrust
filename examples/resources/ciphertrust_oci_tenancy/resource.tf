# Create an OCI tenancy resource using tenancy OCID and name
resource "ciphertrust_oci_tenancy" "tenancy" {
  tenancy_ocid = "tenancy-ocid"
  tenancy_name = "tenancy-name"
}

# Create an OCI tenancy resource from an OCI connection
resource "ciphertrust_oci_connection" "oci_connection" {
  key_file            = "oci-key-file"
  name                = "connection-name"
  pub_key_fingerprint = "public-key-fingerprint"
  region              = "oci-region"
  tenancy_ocid        = "tenancy-ocid"
  user_ocid           = "user-ocid"
}

resource "ciphertrust_oci_tenancy" "tenancy_from_connection" {
  connection_name = ciphertrust_oci_connection.oci_connection.name
}
