# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a CTE Client Profile resource
# with the CipherTrust provider, including setting up profile details.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.0-pre3"
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
}

# Add a resource of type CTE profile with the name TEST_API_Profile1
resource "ciphertrust_cte_profile" "profile" {
  name        = "TEST_API_Profile1"
  description = "Testing profile using Terraforms"

  client_logging_configuration {
    threshold      = "ERROR"
    duplicates     = "ALLOW"
    syslog_enabled = false
    file_enabled   = false
    upload_enabled = false
  }

  cache_settings {
    max_space = 100
    max_files = 205
  }

  syslog_settings {
    local = false
    servers {
      name           = "localhost"
      port           = 22
      protocol       = "TCP"
      message_format = "LEEF"
    }
    syslog_threshold = "ERROR"
  }

  file_settings {
    allow_purge    = false
    max_old_files  = 10
    max_file_size  = 1000000
    file_threshold = "ERROR"
  }
  duplicate_settings {
    suppress_threshold = 5
    suppress_interval  = 600
  }
}

# Output the unique ID of the created CTE profile
output "profile_id" {
    value = ciphertrust_cte_profile.profile.id
}