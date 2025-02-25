# Configure a CipherTrust Transparent Encryption Client on CipherTrust Manager

This example shows how to:
- Create a CipherTrust Transparent Encryption client on CipherTrust Manager of type "FS" or FileSystem

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure CTE Client parameters required to create CTE FS type client
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

## Configure CTE parameters for type "FS"
Edit the CTE configuration resource in main.tf with actual values for type "FS"
```bash
resource "ciphertrust_cte_client" "cte_policy" {
    name                        = "TF_CTE_Client"
    client_type                 = "FS"
    registration_allowed        = true
    communication_enabled       = true
    description                 = "Created via TF"
    password_creation_method    = "GENERATE"
    labels = {
      cloor = "blue"
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