terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "0.11.1"
    }
  }
}

provider "ciphertrust" {}

#Creating a resource set
resource "ciphertrust_cte_resourcegroup" "rg" {
  name        = "TestResourceSet1"
  description = "test111"
  type        = "Directory"
  resources {
    directory          = "/home/testUser1"
    file               = "*"
    include_subfolders = true
  }

  resources {
    directory          = "/home/testUser2"
    file               = "*"
    include_subfolders = true
    hdfs               = true
  }
}