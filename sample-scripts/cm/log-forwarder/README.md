# Adds a log forwarder on CipherTrust Manager

This example shows how to:
- Stream CipherTrust Manager audit/activity logs to an external destination over a pre-existing
  connection

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure the log forwarder resource
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

## Configure the log forwarder

A log forwarder streams to a pre-existing connection (Elasticsearch, Loki, or Syslog) from
CipherTrust Manager's connection manager
(`/v1/connectionmgmt/services/log-forwarders/{elasticsearch,loki,syslog}/connections`). This
provider does not currently expose a resource to create that connection, so `connection_id` must
reference one created outside Terraform (CM console or REST API). Note this is a different
connection registry than `ciphertrust_syslog` (`/v1/configs/syslogs`) — a `ciphertrust_syslog`
resource's `id` will not work here and creation fails with a 404 ("Connection with given ID does
not exists").

Edit the resource configuration in main.tf with an actual connection ID.

```bash
resource "ciphertrust_log_forwarder" "log_forwarder_1" {
  connection_id = "id-of-an-existing-syslog-connection"
  name          = "syslog-forwarder-terraform"
  type          = "syslog"

  syslog_params = {
    forward_logs = {
      activity_kmip        = true
      activity_nae         = true
      client_audit_records = true
      server_audit_records = true
    }
  }
}
```

`type` is immutable — to change it, destroy and recreate the resource. `syslog_params.forward_logs`
is required for a syslog forwarder: CM rejects the create with `NCERRInvalidParamValue` ("Syslog
parameter is required") if it's omitted. For an Elasticsearch or Loki forwarder, set `type`
accordingly and supply the ID of that connection type, plus the matching `elasticsearch_params` or
`loki_params` block instead.

Once a forward-logs flag is set to `true`, it cannot currently be turned off by removing it from
configuration or setting it to `null` — the previous value is preserved.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
