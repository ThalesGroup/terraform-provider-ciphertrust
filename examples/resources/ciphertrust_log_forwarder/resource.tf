# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an log forwarder for ElasticSerach resource
# with the CipherTrust provider, including setting up log forwarder details.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "thalesgroup.com/oss/ciphertrust"
      # Version of the provider to use
      version = "1.0.0"
    }
  }
}

# Configure the CipherTrust provider for authentication
provider "ciphertrust" {
  # The address of the CipherTrust appliance (replace with the actual address)
  address = "https://10.10.10.10"

  # Username for authenticating with the CipherTrust appliance
  username = "admin"

  # Password for authenticating with the CipherTrust appliance
  password = "ChangeMe101!"

  bootstrap = "no"
}

# Add a resource of type log forwarder with the name es_test and type elasticsearch
resource "ciphertrust_log_forwarder" "log_forwarder_1" {
    # connection id of log-forwarder connection (elasticsearch, loki, syslog).
    connection_id = "61dfa3f4-1c14-4827-9dd4-c22988ce10d6"

    # Unique name of the Log Forwarder.
    name = "es_test"

    # Type of the Log Forwarder
    type = "elasticsearch"

    # Optional attributes specifying extra configuration fields specific to Elasticsearch
    elasticsearch_params = {
        indices = {
            activity_kmip = "index_kmip"
            activity_nae = "index_nae"
            server_audit_records = "index_server"
            client_audit_records = "index_client"
        }
    }
}

# Output the unique ID of the created log forwarder
output "log_forwarder_id" {
    value = ciphertrust_log_forwarder.log_forwarder_1.id
}