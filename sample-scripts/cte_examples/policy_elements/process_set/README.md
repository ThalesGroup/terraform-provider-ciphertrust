# Create CTE Policy Process set on Ciphertrust Manager.

This example shows how to:
- Create a CTE Policy Process set on Ciphertrust Manager.

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
resource "resource "ciphertrust_cte_process_set" "process_set" {
    name = "process_set_name"
    description = "process_set_description"
    processes {
            directory = "directory"
            file = "files"
            signature = "signature_set_id"
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