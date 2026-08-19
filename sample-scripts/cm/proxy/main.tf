terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {
  address  = "https://10.10.10.10"
  username = "admin"
  password = "ChangeMe101!"
}

# WARNING: this configures the outbound HTTP/HTTPS proxy for the whole
# CipherTrust Manager appliance. Applying this on a shared CM changes
# connectivity for every user and every other resource that makes outbound
# calls (e.g. cloud connections).
resource "ciphertrust_proxy" "proxy_1" {
  http_proxy  = "http://user01:test12345@10.171.18.190:8080"
  https_proxy = "https://user02:Test12345@10.171.18.190:8081"
  no_proxy    = ["127.0.0.1", "localhost"]
}

output "proxy_id" {
  value = ciphertrust_proxy.proxy_1.id
}
