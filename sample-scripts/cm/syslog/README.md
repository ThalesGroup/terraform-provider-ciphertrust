# Adds a new Syslog connection on CipherTrust Manager

This example shows how to:
- Add a new Syslog connection

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure parameters required to add a Syslog connection
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

## Configure Syslog connection information
Edit the Syslog connection resource configuration in main.tf with actual values
```bash
resource "ciphertrust_syslog" "syslog_1" {
    host = "example.syslog.com"
    transport = "udp"
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