# Configure a set of GuardPaths for a CipherTrust Transparent Encryption client on CipherTrust Manager

This example shows how to:
- Create a set of Guard Paths and sceurity policies guarding those paths for a CipherTrust Transparent Encryption Client

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure GuardPaths and corresponding security policies for a CTE client
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

## Configure CTE Client, a security policy and the corresponding guard points
Edit the configuration resource in main.tf
```bash
resource "ciphertrust_cte_policy" "standard_policy" {
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

resource "ciphertrust_cte_client" "cte_client" {
    name                        = "TF_CTE_Client"
    client_type                 = "FS"
    registration_allowed        = true
    communication_enabled       = true
    description                 = "Created via TF"
    password_creation_method    = "GENERATE"
    labels                      = {
      color = "blue"
    }
}

resource "ciphertrust_cte_client_guardpoint" "dir_auto_gp" {
    guard_paths = ["/opt/path1"]
    guard_point_params = {
        guard_point_type = "directory_auto"
        guard_enabled = true
        policy_id     = ciphertrust_cte_policy.standard_policy.name
    }
    client_id     = ciphertrust_cte_client.cte_client.id
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