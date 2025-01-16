# Activating a CM trial License
resource "ciphertrust_trial_license" "tl" {
  flag = "activate"
}

# Deactivating a CM trial License
resource "ciphertrust_trial_license" "tl" {
  flag = "deactivate"
}