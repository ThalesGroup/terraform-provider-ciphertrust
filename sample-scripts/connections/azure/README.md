# Create an Azure Connection

This example shows how to:
- Create an Azure connection

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure parameters required to create Azure Connection
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

## Configure Azure connection
Edit the azure connection resource in main.tf with actual values
```bash
resource "ciphertrust_azure_connection" "azure_connection" {
  name        = "azure-connection"
  products = [
    "cckm"
  ]
  client_secret ="3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  cloud_name ="AzureCloud"
  client_id ="3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"
  tenant_id = "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  description = "connection description"
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1" = "custom_value1"
    "customer_meta_key2" = "custom_value2"
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