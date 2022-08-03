resource "ciphertrust_domain" "cm_domain" {
  name = "domain_test"
  admins = ["admin"]
  allow_user_management = false
  meta_data = {
      "abc":"xyz"
  }
}