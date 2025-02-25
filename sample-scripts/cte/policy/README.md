# Configure a standard CipherTrust Transparent Encryption policy on CipherTrust Manager

This example shows how to:
- Create a CipherTrust Transparent Encryption policy of standard type with corresponding security rules

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure CTE standard policy parameters that allow all ops
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

## Configure CTE policy
Edit the configuration resource in main.tf
```bash
resource "ciphertrust_cte_policy" "standard_policy" {
    provider        = ciphertrust.primary
    name            = "TF_CTE_Policy"
    policy_type     = "Standard"
    description     = "Created via TF"
    never_deny      = true
    security_rules  = [{
        effect               = "permit,audit"
        action               = "all_ops"
        partial_match        = false
        exclude_resource_set = true
    }]
}
```

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources
Resources must be destroyed before another sample script using the same cloud is run.

```bash
terraform destroy
```

Run this step even if the apply step fails.