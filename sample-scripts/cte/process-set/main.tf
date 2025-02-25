terraform {
  required_providers {
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"
      version = "1.0.0"
    }
  }
}
provider "ciphertrust" {
  address = "https://52.87.160.91"
  username = "admin"
  password = "SamplePassword@1"
  bootstrap = "no"
}

resource "ciphertrust_cte_process_set" "process_set" {
    name = "process_set"
    description = "Process set test"
    processes = [
      {
        directory = "/opt/temp1"
        file = "*"
        signature = "demo"
        labels = {
            key1 = "value1"
        }
      }
    ]
}

output "process_set_id" {
    value = ciphertrust_cte_process_set.process_set.id
}

output "process_set_name" {
    value = ciphertrust_cte_process_set.process_set.name
}