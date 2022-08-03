# Create a HSM-Luna Connection

This example shows how to:
- Create a HSM-Luna network connection
- Create a HSM-Luna connection
- Add a HSM-Luna partition to the connection

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure HSM-Luna parameters required create a HSM-Luna keys
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

Create a ~/.ciphertrust/config file and configure these keys with your values.

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

## Configure HSM-Luna Credentials and Partitions

### Configure for all HSM-Luna examples

Update values in scripts/hsm_vars.sh and run the script.

This updates all hsm_vars.tf files found in the subdirectories.

### Configure for this example only

Edit hsm_vars.tf in this directory and update with your values.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
