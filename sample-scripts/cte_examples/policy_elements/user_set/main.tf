terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "0.10.6-beta"
    }
  }
}

provider "ciphertrust" {}

#Creating an user set
resource "ciphertrust_cte_user_set" "user_set" {
  name        = "UserSet"
  description = "Test User set"
  users {
    uname     = "root"
    uid       = 1000
    gname     = "rootGroup"
    gid       = 1000
    os_domain = "windows"
  }
}