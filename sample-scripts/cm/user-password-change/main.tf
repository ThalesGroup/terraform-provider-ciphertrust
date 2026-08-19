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

# A throwaway user so this example is self-contained: the password change
# below targets this user rather than a real one.
resource "ciphertrust_user" "test_user" {
  name     = "frank"
  email    = "frank@local"
  username = "frank"
  password = "ChangeMe101!"
}

# This is a write-only, one-shot action modeled as a resource: applying it
# changes the password immediately. terraform destroy does NOT revert it,
# and updates are not supported — delete and recreate this resource (with
# password set to the new current value) to change the password again.
resource "ciphertrust_cm_user_password_change" "pwd_change" {
  username     = ciphertrust_user.test_user.username
  password     = "ChangeMe101!"
  new_password = "ChangeMe201!"

  depends_on = [ciphertrust_user.test_user]
}
