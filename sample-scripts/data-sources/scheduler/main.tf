terraform {
  required_providers {
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"
      version = "1.0.0"
    }
  }
}

provider "ciphertrust" {
  address = "https://10.10.10.10"
  username = "admin"
  password = "Sample@34"
  bootstrap = "no"
}

data "ciphertrust_scheduler_list" "jobs" {
  filters = {
          name = "db_backup1-terraform"
    #    id = "149234d7-557d-4ea9-bc0e-f15891fe632c"
    #    operation = "key_rotation"
    #    disabled = true
  }
}

output "scheduler_jobs" {
  value = data.ciphertrust_scheduler_list.jobs
}
