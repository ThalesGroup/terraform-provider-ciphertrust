terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {
  address  = "https://10.10.10.10"
  username = "admin"
  password = "ChangeMe101!"
}

# A log forwarder streams to a pre-existing Syslog/Elasticsearch/Loki
# connection from CipherTrust Manager's connection manager
# (/v1/connectionmgmt/services/log-forwarders/...). This provider does not
# currently expose a resource to create that connection, so connection_id
# must reference one created outside Terraform (CM console or REST API).
# Note this is a different connection registry than ciphertrust_syslog
# (/v1/configs/syslogs), so a ciphertrust_syslog resource's id will NOT work
# here.
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

output "log_forwarder_id" {
  value = ciphertrust_log_forwarder.log_forwarder_1.id
}
