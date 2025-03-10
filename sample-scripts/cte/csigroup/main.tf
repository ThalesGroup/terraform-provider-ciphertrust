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

resource "ciphertrust_cte_csigroup" "csigroup" {
    kubernetes_namespace = "default"
    kubernetes_storage_class = "tf_class"
    name = "TF_CSI_Group"
    description = "Created via TF"
}