# Create a new domain on CipherTrust Manager

This example shows how to:
- Create a Domain

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure parameters required to create Domain
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

## Configure Domain information
Edit the domain resource configuration in main.tf with actual values
```bash
resource "ciphertrust_domain" "testDomain" {
  name = "domain_tf"
  admins = ["admin"]
  allow_user_management = false
  meta_data = {
      "abc": "xyz"
  }
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