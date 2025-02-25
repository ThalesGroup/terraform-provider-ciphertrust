terraform {
	required_providers {
	  ciphertrust = {
		source = "thalesgroup.com/oss/ciphertrust"
		version = "1.0.0"
	  }
	}
}

provider "ciphertrust" {
    address = "https://192.168.2.158"
    username = "admin"
    password = "ChangeIt01!"
    bootstrap = "no"
    alias = "primary"
}

resource "ciphertrust_cte_csigroup" "csigroup" {
    provider = ciphertrust.primary
    kubernetes_namespace = "default"
    kubernetes_storage_class = "tf_class"
    name = "TF_CSI_Group"
    description = "Created via TF"
}