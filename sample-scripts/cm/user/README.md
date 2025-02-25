# Adds a new User on CipherTrust Manager

This example shows how to:
- Add a new CipherTrust Manager User

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure parameters required to add a user on CipherTrust Manager
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

## Configure User resource information
Edit the User resource configuration in main.tf with actual values
```bash
resource "ciphertrust_cm_user" "testUser" {
  name="frank"
  email="frank@local"
  username="frank"
  password="ChangeIt01!"
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