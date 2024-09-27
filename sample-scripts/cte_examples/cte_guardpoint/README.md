# Create CTE Guardpoint on Ciphertrust Manager.

This example shows how to:
- Create a Guardpoint on Ciphertrust Manager.

The following steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Run the example

## Configure CipherTrust Manager

### Use environment variables

```bash
export CM_ADDRESS=https://cm-address
export CM_USERNAME=cm-username
export CM_PASSWORD=cm-password
export CM_DOMAIN=cm-domain
```
### Use a configuration file

Create a ~/.ciphertrust/config file and configure these keys with your values

```bash
address = https://cm-address
username = cm-username
password = cm-password
domain = cm-domain
```

### Edit the provider block in main.tf

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
  domain   = "cm-domain"
}
```


### Edit the connection resource in main.tf

```bash
resource "ciphertrust_cte_guardpoint" "cte_gp" {
    gp_type = "gp_type"
    guard_enabled = true
    guard_paths = ["guard_path_list"]
    policy_id = "API_LDT_Policy1" 
    client_id = "hostname"
}
```

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

Resources must be destroyed before another sample script using the same clouds is run.

```bash
terraform destroy
```
Run this step even if the apply step fails.