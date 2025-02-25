# Adds a new property on CipherTrust Manager

This example shows how to:
- Add a new CipherTrust Manager property

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure parameters required to add a property
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

## Configure property information
Edit the property resource configuration in main.tf with actual values
```bash
resource "ciphertrust_property" "property_1" {
    name = "ENABLE_RECORDS_DB_STORE"
    value = "false"
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