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

resource "ciphertrust_cte_process_set" "process_set" {
    name = "process_set_tf"

    description = "Process set test"

    processes = [
      {
        directory = "/usr/bin"
        file = "ls"
        signature = "demo"
      }
    ]
}

