# Retrieve details using the CipherTrust key ID
data "ciphertrust_gcp_key" "by_ciphertrust_id" {
  key_id = "6f4134bf-0007-42db-bc0b-e11e5bfbe782"
}

# Retrieve details using the key name and keyring
data "ciphertrust_gcp_key" "by_keyname_and_keyring" {
  name     = "key-name"
  key_ring = "projects/my-project/locations/my-location/keyRings/my-keyring"
}
