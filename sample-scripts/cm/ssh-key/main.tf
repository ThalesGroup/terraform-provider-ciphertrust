terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.1"
    }
  }
}

# ciphertrust_cm_ssh_key supports both initial bootstrap (bootstrap = "yes",
# only address needed) and standard credentials-based (bootstrap = "no")
# modes. This example uses bootstrap mode.
provider "ciphertrust" {
  address   = "https://10.10.10.10"
  bootstrap = "yes"
}

resource "ciphertrust_cm_ssh_key" "ssh_key" {
  key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIVGP8Ojyum6d7/r2Q1oihXfEcmEgzKUOCcNue2ovIRaxnqdFBTIEVnPBu6R0kMvBHvhyYpqQaLyCa6QhYgmzLA16A7M0+QSdBz+pFC6cMF6VK9b/lXgLek3aD4s+ynCc+/RF+n2AcS5j+JmkvQeOntY/WhmvCwJJpk6cmNfpnqfF/C8ExvGC3IPBCaVtHU2eIHvT0rIVwGYNZulrryeoPQZ2vH4cUPCDHxFeWTGCjXxPvy0JSoY0Z5mKJtxWLnEgIFzTUYiDueKM7HTrj5LPzov3ohB5bhNdiA+wLljFL7da8OvNhXp6aqCgg9ezs8df3bNSkWiaf24R/28sTeDuF"
}

output "ssh_key_id" {
  value = ciphertrust_cm_ssh_key.ssh_key.id
}
