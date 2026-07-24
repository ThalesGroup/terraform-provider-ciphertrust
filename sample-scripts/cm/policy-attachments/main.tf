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

resource "ciphertrust_policies" "policy" {
  	name    =   "mypolicy"
    actions =   ["ReadKey"]
    allow   =   true
    effect  =   "allow"
    conditions = [{
        path   = "context.resource.alg"
        op     = "equals"
        values = ["aes","rsa"]
    }]
}

resource "ciphertrust_policy_attachments" "policy_attachment" {
  	policy = "mypolicy"
	principal_selector = {
		acct = "pers-jsmith"
		user = "apitestuser"
	}
	depends_on = [ciphertrust_policies.policy]
}

output "cm_policy_attachment_id" {
	value = ciphertrust_policy_attachments.policy_attachment.id
}