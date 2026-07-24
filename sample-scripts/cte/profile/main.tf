terraform {
  required_providers {
    ciphertrust = {
      source = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {
	address = "https://10.10.10.10"
	username = "admin"
	password = "ChangeMe101!"
}

#Creating cte client profile
resource "ciphertrust_cte_profile" "profile" {
  name        = "TEST_API_Profile1"
  description = "Testing profile using Terraforms"

  cache_settings =  {
    max_space = 500
    max_files = 250
  }


  concise_logging = true

  duplicate_settings = {
    suppress_threshold = 20
    suppress_interval  = 500
  }

  file_settings = {
    allow_purge    = true
    max_old_files  = 10
    max_file_size  = 2000000
    file_threshold = "ERROR"
  }

  client_logging_configuration = {
   threshold = "ERROR",
		duplicates = "SUPPRESS",
		syslog_enabled = true,
		file_enabled = true,
		upload_enabled = true
  }

  syslog_settings = {
    local = true
    servers = [{
      name           = "localhost"
      port           = 22
      protocol       = "TCP"
      message_format = "LEEF"
    }]
    syslog_threshold = "ERROR"
  }

	upload_settings =  {
		min_interval = 10
		max_interval = 20
		max_messages = 2000
		connection_timeout = 50
		job_completion_timeout = 600
		drop_if_busy = true
		upload_threshold = "ERROR"
	}

}