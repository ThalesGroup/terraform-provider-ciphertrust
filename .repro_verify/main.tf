terraform {
  required_providers {
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"
    }
  }
}

provider "ciphertrust" {
  address        = "https://10.171.98.28"
  username       = "admin"
  password       = "Asdf@1234"
  bootstrap      = "no"
  domain         = "root"
  auth_domain    = "root"
  no_ssl_verify  = true
}

resource "ciphertrust_aws_connection" "test" {
  name              = "tfrepro-tfin-333-fe8bf4-1"
  access_key_id     = "AKIAIOSFODNN7EXAMPLE"
  secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  products          = ["azure"]
}
