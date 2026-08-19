terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {
  address  = "https://10.10.10.10"
  username = "admin"
  password = "ChangeMe101!"
}

# WARNING: changing the port of a default interface (web, nae, kmip) restarts
# CM services cluster-wide. Treat this as a planned, disruptive change.
#
# `name` is documented as settable for interface_type "web"/"snmp", but live
# testing against CM rejects it on create ("Name is not allowed while
# creating WEB interface") regardless of interface_type — CM appears to only
# allow setting `name` on an existing interface via update, not at create
# time. Omit it here; if you need a specific name, set it in a follow-up
# apply after the interface exists.
resource "ciphertrust_interface" "certificate" {
  interface_type = "web"
  port           = 9005

  certificate = {
    generate = true
    format   = "PEM"
  }
}

output "interface_id" {
  value = ciphertrust_interface.certificate.id
}
