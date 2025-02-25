terraform {
  required_providers {
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"
      version = "1.0.0"
    }
  }
}

provider "ciphertrust" {
  address = "https://10.10.10.10"
  username = "admin"
  password = "SamplePassword@1"
  bootstrap = "no"
}

data "ciphertrust_scp_connection_list" "example_scp_connection" {
  filters = {
    labels = "s=S"
  }
}

output "scp_connection_details" {
  value = data.ciphertrust_scp_connection_list.example_scp_connection
}
