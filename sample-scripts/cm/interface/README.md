# Configures a CipherTrust Manager interface

This example shows how to:
- Configure a service endpoint interface (web, NAE, or KMIP) on CipherTrust Manager

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure the interface resource
- Run the example

**Warning:** changing the port of a default interface (`web`, `nae`, `kmip`) restarts CM services
cluster-wide. Test against a non-production CipherTrust Manager, and treat this as a planned,
disruptive change rather than something to apply casually.

## Configure CipherTrust Manager

### Edit the provider block in main.tf

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
}
```

## Configure the interface

Edit the interface resource configuration in main.tf with actual values.

```bash
resource "ciphertrust_interface" "certificate" {
  interface_type = "web"
  port           = 9005

  certificate = {
    generate = true
    format   = "PEM"
  }
}
```

Set `interface_type` explicitly — CM otherwise defaults new interfaces to `nae`. The schema
describes `name` as settable for `web`/`snmp` interfaces, but live testing shows CM rejects it on
**create** ("Name is not allowed while creating WEB interface") regardless of `interface_type` — it
can only be set on an existing interface via a later update, not at creation time. This example
omits it accordingly.

`certificate.generate = true` has CipherTrust Manager create a new self-signed certificate.
Alternatively, supply `certificate.certificate_chain` with PEM or base64-encoded PKCS12 data to
bring your own certificate.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
