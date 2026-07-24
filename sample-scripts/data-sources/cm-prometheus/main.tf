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

resource "ciphertrust_cm_prometheus" "cm_prometheus" {
  enabled = true
}

data "ciphertrust_cm_prometheus_status" "status" {
  depends_on = [ciphertrust_cm_prometheus.cm_prometheus]
}

output "prometheus_status" {
  value = data.ciphertrust_cm_prometheus_status.status
}
