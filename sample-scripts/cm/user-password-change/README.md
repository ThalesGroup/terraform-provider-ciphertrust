# Changes a CipherTrust Manager user's password

This example shows how to:
- Change the password of a CipherTrust Manager local user

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure the password change resource
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

## Configure the password change

This example creates a throwaway user first so it is self-contained, then changes that user's
password. Edit both resources in main.tf with actual values.

```bash
resource "ciphertrust_user" "test_user" {
  name     = "frank"
  email    = "frank@local"
  username = "frank"
  password = "ChangeMe101!"
}

resource "ciphertrust_cm_user_password_change" "pwd_change" {
  username     = ciphertrust_user.test_user.username
  password     = "ChangeMe101!"
  new_password = "ChangeMe201!"

  depends_on = [ciphertrust_user.test_user]
}
```

`ciphertrust_cm_user_password_change` is a write-only, one-shot action modeled as a resource:
applying it changes the password immediately. `terraform destroy` does **not** revert the
password — it only removes the resource from state. Updates are not supported either; to change
the password again, delete and recreate the resource with `password` set to the current value and
`new_password` set to the next one.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

Destroying this configuration deletes the throwaway user entirely, which is what actually cleans
up the changed password — `ciphertrust_cm_user_password_change` itself does not revert anything.

```bash
terraform destroy
```
