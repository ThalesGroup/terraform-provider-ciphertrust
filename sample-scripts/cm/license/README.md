# Adds a license to CipherTrust Manager

This example shows how to:
- Activate a license on CipherTrust Manager

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure the license resource
- Run the example

## Configure CipherTrust Manager

### Edit the provider block in main.tf

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
}
```

## Configure the license

Edit the license resource configuration in main.tf with your actual CipherTrust Manager license
string.

```bash
resource "ciphertrust_license" "license_1" {
  license = "your-actual-license-string"
}
```

This resource does not support updates — to change the license, destroy and recreate the
resource. `license` is write-only and is never stored in Terraform state or plan artifacts.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
