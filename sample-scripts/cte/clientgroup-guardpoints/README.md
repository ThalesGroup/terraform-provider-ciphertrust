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
    }]
}

resource "ciphertrust_cte_client_group" "cte_client_group" {
    name         = "TF_CTE_ClientGroup"
    cluster_type = "NON-CLUSTER"
    description  = "Created via TF"
}

resource "ciphertrust_cte_clientgroup_guardpoint" "dir_auto_gp_cg" {
  client_group_id = ciphertrust_cte_client_group.cte_client_group.id
  guard_points = {
    "/test/gp_cg1" = {
      guard_point_params = {
       guard_point_type = "directory_manual"
        policy_id        = ciphertrust_cte_policy.standard_policy.id
        #mfa_enabled = true
        #guard_enabled = false
      }
    }
  }
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