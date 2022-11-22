# Get the GCP keyring data using the Terraform resource id
data "ciphertrust_gcp_keyring" "by_terraform_id" {
  id = ciphertrust_gcp_keyring.gcp_keyring.id
}

# Get the GCP keyring data using the keyring name
data "ciphertrust_gcp_keyring" "by_keyring_name" {
  name = ciphertrust_gcp_keyring.gcp_keyring.name
}
