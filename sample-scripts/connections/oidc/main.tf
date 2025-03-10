terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "0.10.8-beta"
    }
  }
}

provider "ciphertrust" {}

#Creating a Oidc connection.
resource "ciphertrust_oidc_connection" "OIDCConnection" {
  name          = "TESTOIDC."
  description   = "Description about the connections."
  products      = ["cte"]
  client_id     = "testclient"
  client_secret = "redacted"
  url           = "testnew.com"
}
