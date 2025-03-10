terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "0.10.9-beta"
    }
  }
}

provider "ciphertrust" {}

#Creating a Smb connection.
resource "ciphertrust_smb_connection" "SmbConnection" {
  name        = "TestSmb"
  description = "Description about the connections."
  username    = "admin"
  password    = "redacted"
  domain      = "root"
}

#Creating a Smb connection with host and port.
resource "ciphertrust_smb_connection" "SmbConnection" {
  name        = "TestSmb1"
  description = "Description about the connections."
  username    = "admin"
  host        = "abcd.com"
  port        = "445"
  password    = "redacted"
  domain      = "root"
}