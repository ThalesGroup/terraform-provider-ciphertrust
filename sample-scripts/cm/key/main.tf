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
}

data "ciphertrust_cm_users_list" "users_list" {
  filters = {
    username = "admin"
  }
}

resource "ciphertrust_cm_key" "test_key" {
  name="test_key"
  algorithm="aes"
  size=256
  usage_mask=76
  undeletable=false
  unexportable=false
  meta={
    owner_id=tolist(data.ciphertrust_cm_users_list.users_list.users)[0].user_id
    permissions={
      decrypt_with_key=["CTE Clients"]
      encrypt_with_key=["CTE Clients"]
      export_key=["CTE Clients"]
      mac_verify_with_key=["CTE Clients"]
      mac_with_key=["CTE Clients"]
      read_key=["CTE Clients"]
      sign_verify_with_key=["CTE Clients"]
      sign_with_key=["CTE Clients"]
      use_key=["CTE Clients"]
    }
    cte={
      persistent_on_client=true
      encryption_mode="CBC"
      cte_versioned=false
    }
    xts=false
  }
}

output "test_key_id" {
	value = ciphertrust_cm_key.test_key.id
}