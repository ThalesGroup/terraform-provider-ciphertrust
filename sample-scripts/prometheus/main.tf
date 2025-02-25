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
  password = "SamplePass_0"
  bootstrap = "no"
}

resource "ciphertrust_cm_prometheus" "cm_prometheus" {
  enabled = true
}

output "prometheus" {
  value = ciphertrust_cm_prometheus.cm_prometheus.enabled
}
