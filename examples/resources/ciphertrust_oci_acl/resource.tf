# Create a tenancy resource
resource "ciphertrust_oci_tenancy" "oci_tenancy" {
  tenancy_ocid = "tenancy-ocid"
  tenancy_name = "tenancy-name"
}

# Create an OCI issuer resource
resource "ciphertrust_oci_issuer" "oci_issuer" {
  name              = "issuer-name"
  openid_config_url = "open-config-url"
}

# Create an OCI external vault resource
resource "ciphertrust_oci_external_vault" "external_vault" {
  client_application_id = "oci-client-application-id"
  issuer_id             = ciphertrust_oci_issuer.oci_issuer.id
  tenancy_id            = ciphertrust_oci_tenancy.oci_tenancy.id
  vault_name            = "vault-name"
}

# Create a user
resource "ciphertrust_user" "user" {
  username = "username"
  password = "password"
}

# Create another user which will be added to a group
resource "ciphertrust_user" "group_user" {
  username = "group_user"
  password = "password"
}

# Create a group and add the user
resource "ciphertrust_groups" "group" {
  name     = "group"
  user_ids = [ciphertrust_user.group_user.id]
}

# Users must be a member of the CCKM Users group to perform operations on cloud keys
resource "ciphertrust_groups" "cckm_users" {
  name = "CCKM Users"
  user_ids = [
    ciphertrust_user.user.id,
    ciphertrust_user.group_user.id,
  ]
}

# Users must be a member of the Key Users group to perform operations on CipherTrust keys
resource "ciphertrust_groups" "key_users" {
  name = "Key Users"
  user_ids = [
    ciphertrust_user.group_user.id,
  ]
}

# Add an acl for the user to the vault
resource "ciphertrust_oci_acl" "user_acl" {
  actions  = ["viewhyokkey", "hyokkeycreate"]
  user_id  = ciphertrust_user.user.id
  vault_id = ciphertrust_oci_external_vault.external_vault.id
}

# Add an acl for the group to the vault
resource "ciphertrust_oci_acl" "group_acl" {
  actions  = ["viewhyokkey", "hyokkeycreate", "hyokkeydelete"]
  group    = ciphertrust_groups.group.id
  vault_id = ciphertrust_oci_external_vault.external_vault.id
}
