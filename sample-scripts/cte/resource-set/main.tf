terraform {
  required_providers {
    ciphertrust = {
      source = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {

  address = "https://10.10.10.10"

  username = "admin"

  password = "ChangeMe101!"
}

resource "ciphertrust_cte_resource_set" "resource_set" {
    name = "resource_set_tf"

    description = "ResourceSet Terraform"

    resources = [
      {
        directory = "/opt/temp1"
        file = "file.txt"
        include_subfolders = true
        hdfs = false
      }
    ]

}
