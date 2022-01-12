# Get the GCP key data using the terraform id
data "ciphertrust_gcp_key" "by_terraform_id" {
  gcp_cloud_resource_name = ciphertrust_gcp_key.gcp_key.id
}

# Get the GCP key data using the CipherTrust key id
data "ciphertrust_gcp_key" "by_ciphertrust_id" {
  key_id = ciphertrust_gcp_key.gcp_key.key_id
}

# Get the GCP key data using key name
data "ciphertrust_gcp_key" "by_key_name" {
  name = "gcp_key_name"
}

# Get the GCP key data using key name and other values
data "ciphertrust_gcp_key" "by_multiple_values_ex1" {
  name        = "gcp_key_name"
  key_ring    = "projects/gcp_project_id/locations/project_location/keyRings/gcp_keyring_name"
  project_id  = "gcp_project_id"
  location_id = "project_location"
}

# Get the GCP key data using key name and other values
data "ciphertrust_gcp_key" "by_multiple_values_ex2" {
  name        = "gcp_key_name"
  key_ring_id = "gcp_keyring_name"
  project_id  = "gcp_project_id"
  location_id = "project_location""
}
