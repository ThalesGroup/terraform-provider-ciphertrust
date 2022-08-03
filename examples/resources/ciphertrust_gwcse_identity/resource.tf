# Create a CSE identity using only issuer
resource "ciphertrust_gwcse_identity" "cse_identity_issuer_only" {
  name   = "identity-name"
  issuer = "https://terraform-example.auth0.com/"
}

# Create a CSE identity using issuer and jwks_url
resource "ciphertrust_gwcse_identity" "cse_identity_issuer_and_jwks" {
  name     = "identity-name"
  issuer   = "https://terraform-example.auth0.com/"
  jwks_url = "https://terraform-example.auth0.com/.well-known/jwks.json"
}

# Create a CSE identity using only open_id_configuration_url
resource "ciphertrust_gwcse_identity" "cse_identity_open_id" {
  name   = "identity-name"
  open_id_configuration_url = "https://terraform-example.auth0.com/.well-known/openid-configuration"
}

# Create a CSE identity using all input parameters
resource "ciphertrust_gwcse_identity" "cse_identity_with_all" {
  name                      = "identity-name"
  issuer                    = "https://terraform-example.auth0.com/"
  jwks_url                  = "https://terraform-example.auth0.com/.well-known/jwks.json"
  open_id_configuration_url = "https://terraform-example.auth0.com/.well-known/openid-configuration"
}

# Create ciphertrust_gwcse_endpoint using a ciphertrust_gwcse_identity resource ID
resource "ciphertrust_gwcse_endpoint" "cse_endpoint" {
  name                    = "endpoint-name"
  cse_identity_id         = ciphertrust_gwcse_identity.cse_identity_open_id.id
  authentication_audience = ["authentication_audience"]
  endpoint_url_hostname   = "terraform.example.com"
  meta                    = "some information to store with endpoint"
}

