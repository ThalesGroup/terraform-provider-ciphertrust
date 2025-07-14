resource "ciphertrust_oci_vault" "vault" {
  # Required parameters
  connection_id    = ciphertrust_oci_connection.connection.name
  region           = "oci-region"
  vault_id         = "vault-ocid"
  # Optional parameters
  bucket_name      = "bucket-name"
  bucket_namespace = "bucket-namespace"
}
