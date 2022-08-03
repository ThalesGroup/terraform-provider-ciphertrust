# Create a CSE identity
resource "ciphertrust_gwcse_identity" "cse_identity" {
  name   = "identity-name"
  open_id_configuration_url = "https://terraform-example.auth0.com/.well-known/openid-configuration"
}

resource "ciphertrust_gwcse_endpoint" "cse_endpoint" {
  name                    = "endpoint-name"
  cse_identity_id         = ciphertrust_gwcse_identity.cse_identity.id
  authentication_audience = ["authentication_audience"]
  endpoint_url_hostname   = "terraform.example.com"
  meta                    = "some information to store with endpoint"
}
