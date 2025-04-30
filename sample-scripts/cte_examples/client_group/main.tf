terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = ".10.10-beta"
    }
  }
}

provider "ciphertrust" {}

# Creating a clientgroup with cluster_type as NON_CLUSTER
resource "ciphertrust_cte_clientgroup" "clientgroup" {
  name                     = "testclientgroup"
  description              = "Desc of client group"
  communication_enabled    = false
  password_creation_method = "MANUAL"
  password                 = "redacted"
  profile_id               = "profile_id cte profile"
  cluster_type             = "NON-CLUSTER"
}

# Creating a clientgroup with cluster_type as HDFS 
resource "ciphertrust_cte_clientgroup" "clientgroup" {
  name                     = "testclientgroup"
  description              = "Desc of client group"
  communication_enabled    = false
  password_creation_method = "MANUAL"
  password                 = "redacted"
  profile_id               = "profile_id cte profile"
  cluster_type             = "HDFS"
}