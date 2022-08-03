resource "ciphertrust_user" "user_admin1" {
  username = "secure_admin"
  password = "Test123#"
  email = "test@test.com"
  name = "Mr. Test"
  is_domain_user = false
  prevent_ui_login = true
  password_change_required = true
  user_metadata = {
    "abc" = "123"
    "def" = "456"
  }
}