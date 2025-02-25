terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "1.0.0"
    }
  }
}

provider "ciphertrust" {}

# Creating a client with Password_creation method as GENERATE 
resource "ciphertrust_cte_client" "client" {
  name                     = "test_client"
  password_creation_method = "GENERATE"
  description              = "Temp host for testing."
  registration_allowed     = true
  communication_enabled    = true
  client_type              = "FS"
}

# Creating a client with Password_creation method as MANUAL 
resource "ciphertrust_cte_client" "client" {
  name                     = "test_client1"
  password_creation_method = "MANUAL"
  password                 = "redacted"
  description              = "Temp host for testing."
  registration_allowed     = true
  communication_enabled    = true
  client_type              = "FS"
}