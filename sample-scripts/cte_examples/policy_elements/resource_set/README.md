# Create CTE Policy Resource set on Ciphertrust Manager.

This example shows how to:
- Create a CTE Policy Resource set on Ciphertrust Manager.

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
resource "ciphertrust_cte_resourcegroup" "rg" {
        name="resource_set_name"
        description = "resource_set description"
        type = "resource_type"
        resources {
        directory = "directory"
        file = "files"
        include_subfolders = true
        }
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