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

resource "ciphertrust_password_policy" "CustomPasswordPolicy" {
	policy_name = "testCustomPolicyName"
    inclusive_min_upper_case = 1
    inclusive_min_lower_case = 1
    inclusive_min_digits = 1
    inclusive_min_other = 0
    inclusive_min_total_length = 8
    inclusive_max_total_length = 30
    password_history_threshold = 0
    failed_logins_lockout_thresholds = [0, 0, 30]
    password_lifetime = 30
    password_change_min_days = 1
}

output "customPolicy" {
	value = ciphertrust_password_policy.CustomPasswordPolicy.policy_name
}