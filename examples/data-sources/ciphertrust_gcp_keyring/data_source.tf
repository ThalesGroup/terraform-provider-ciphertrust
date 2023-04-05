# Get the GCP keyring data using the keyring name
data "ciphertrust_gcp_keyring" "by_keyring_name" {
  name = "projects/my-project/locations/my-location/keyRings/keyring"
}
