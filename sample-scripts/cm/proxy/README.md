# Configures the CipherTrust Manager outbound proxy

This example shows how to:
- Configure outbound HTTP/HTTPS proxy settings for the CipherTrust Manager appliance

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure the proxy resource
- Run the example

**Warning:** this is a single, appliance-wide setting. Applying it on a shared CipherTrust Manager
changes outbound connectivity for every user and every other resource that makes outbound calls
(e.g. cloud connections). Test against a non-production CipherTrust Manager.

## Configure CipherTrust Manager

### Edit the provider block in main.tf

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
}
```

## Configure the proxy

Edit the proxy resource configuration in main.tf with actual values.

```bash
resource "ciphertrust_proxy" "proxy_1" {
  http_proxy  = "http://user:password@proxy-host:8080"
  https_proxy = "https://user:password@proxy-host:8081"
  no_proxy    = ["127.0.0.1", "localhost"]
}
```

All attributes are optional; set only the ones you need.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
