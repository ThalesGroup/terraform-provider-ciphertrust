terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "0.10.8-beta"
    }
  }
}

provider "ciphertrust" {}

#Creating cte client profile
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