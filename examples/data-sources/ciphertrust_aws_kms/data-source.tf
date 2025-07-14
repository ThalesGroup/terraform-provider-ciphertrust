data "ciphertrust_oci_kms_list" "ciphertrust_kms_list" {
  # Optional parameters
  filters = {
    limit = -1
  }
}
