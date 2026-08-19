# Adds an SSH public key to CipherTrust Manager

This example shows how to:
- Add an SSH public key to the CipherTrust Manager appliance

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure the SSH key resource
- Run the example

## Configure CipherTrust Manager

### Edit the provider block in main.tf

`ciphertrust_cm_ssh_key` works in both bootstrap mode (only `address` needed) and standard
credentials-based mode.

```bash
# Bootstrap mode
provider "ciphertrust" {
  address   = "https://cm-address"
  bootstrap = "yes"
}
```

```bash
# Standard mode
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
}
```

## Configure the SSH key

Edit the resource configuration in main.tf with an actual public key.

```bash
resource "ciphertrust_cm_ssh_key" "ssh_key" {
  key = "ssh-rsa AAAA..."
}
```

This resource does not support updates — the key cannot be modified after creation. To use a
different key, destroy and recreate the resource.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
