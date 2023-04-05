resource "ciphertrust_password_policy" "PasswordPolicy"{
	inclusive_min_upper_case = 2 
	inclusive_min_lower_case = 2 
	inclusive_min_digits = 2 
	inclusive_min_other = 2 
	inclusive_min_total_length = 10
	inclusive_max_total_length = 50 
	password_history_threshold = 10 
	failed_logins_lockout_thresholds = [0, 0, 1, 1]
	password_lifetime = 20
	password_change_min_days = 100
}
