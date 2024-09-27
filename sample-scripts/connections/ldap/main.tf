terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "0.10.6-beta"
    }
  }
}

provider "ciphertrust" {}

#Creating a Ldap connection.
resource "ciphertrust_ldap_connection" "ldapConnection" {
  name                 = "TestLdap"
  description          = "Description about the connections."
  url                  = "test1.com"
  products             = ["cte"]
  group_member_field   = "member1"
  group_name_attribute = "groupname1"
  group_base_dn        = "planetexprress1"
  group_filter         = "group1"
  search_filter        = "User1"
  user_login_attribute = "uid1"
  bind_dn              = "planetexpress1"
  base_dn              = "planetexpress1"
  bind_password        = "redacted"
}
