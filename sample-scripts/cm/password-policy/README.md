# Add or update user's password policy on CipherTrust Manager

This example shows how to:
- Add a new user's password policy
- Update an existing password policy

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure parameters required to add a new password policy
- Configure parameters to update an existing password policy including the default i.e. "global"
- Run the example


## Configure CipherTrust Manager

### Edit the provider block in main.tf

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
  domain   = "cm-domain"
  bootstrap = "no"
}
```

## Configure new password policy information
Edit the new Password Policy resource configuration in main.tf with actual values
```bash
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
```

## Configure existing password policy update information
Edit the existing Password Policy resource configuration in main.tf with actual values.
Leave policy_name to update the default "global" policy
```bash
resource "ciphertrust_password_policy" "GlobalPasswordPolicy" {
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
```

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources
Resources must be destroyed before another sample script using the same domain name is run.

```bash
terraform destroy
```

Run this step even if the apply step fails.