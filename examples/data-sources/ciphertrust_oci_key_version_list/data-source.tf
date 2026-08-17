# Sort key versions by creation date, newest first.
data "ciphertrust_oci_key_version_list" "sorted" {
  key_id = "cm-key-id"
  filters = {
    sort = "-createdAt"
  }
}

# List key versions by origin, returning all matches.
data "ciphertrust_oci_key_version_list" "by_origin" {
  key_id = "cm-key-id"
  filters = {
    origin = "INTERNAL"
    limit  = "-1"
  }
}
