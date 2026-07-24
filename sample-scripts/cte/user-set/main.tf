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

resource "ciphertrust_cte_user_set" "user_set" {
   name = "User_set_tf"

   description = "UserSet Terraform"
   users = [
      {
        uname = "john.doe"
        uid   = 1000
        gname = "sudo"
        gid   = 0
      },
      {
        uname = "test.user"
      }
    ]

}
