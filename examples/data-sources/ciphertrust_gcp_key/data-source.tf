# Retrieve details using the terraform ID
data "ciphertrust_gcp_key" "by_terraform_id" {
  gcp_cloud_resource_name = ciphertrust_gcp_key.gcp_key.id
}

# Retrieve details using the CipherTrust key ID
data "ciphertrust_gcp_key" "by_ciphertrust_id" {
  key_id = ciphertrust_gcp_key.gcp_key.key_id
}

# Retrieve details using the key name
data "ciphertrust_gcp_key" "by_key_name" {
  name = ciphertrust_gcp_key.gcp_key.name
}

# Retrieve details using the key name and the keyring name
data "ciphertrust_gcp_key" "by_multiple_values_ex1" {
  name        = ciphertrust_gcp_key.gcp_key.name
  key_ring    = ciphertrust_gcp_key.gcp_key.key_ring_name
}
