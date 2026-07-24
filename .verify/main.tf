# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MIT

terraform {
  required_providers {
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"
    }
  }
}

provider "ciphertrust" {
  address       = "https://10.171.98.28"
  username      = "admin"
  password      = "Asdf@1234"
  bootstrap     = "no"
  domain        = "root"
  auth_domain   = "root"
  no_ssl_verify = true
}

# Phase 2 config: key and key_type added to an existing NTP resource whose
# Phase 1 state had those Optional fields null. Fixed provider should show
# -/+ destroy-and-recreate (RequiresReplaceIfConfigured), not a silent in-place update.
resource "ciphertrust_ntp" "tfrepro-tfin-351-73b1f3" {
  host     = "0.pool.ntp.org"
  key      = "tfrepro-tfin-351-12f1cd-testkey"
  key_type = "SHA-256"
}
