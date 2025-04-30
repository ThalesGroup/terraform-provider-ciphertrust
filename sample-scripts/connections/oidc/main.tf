terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = ".10.10-beta"
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
