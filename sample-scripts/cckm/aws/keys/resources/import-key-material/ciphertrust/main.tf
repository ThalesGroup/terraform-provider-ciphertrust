terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name          = "tf-import-${lower(random_id.random.hex)}"
  kms_name                 = "tf-import-${lower(random_id.random.hex)}"
  aes_key_name             = "tf-import-aes-${lower(random_id.random.hex)}"
  hmac_key_name            = "tf-import-hmac-256-${lower(random_id.random.hex)}"
  rsa_key_name             = "tf-import-rsa2048-${lower(random_id.random.hex)}"
  ecc_nist_p384_key_name   = "tf-import-ecc_nist_p384-${lower(random_id.random.hex)}"
  ecc_nist_p521_key_name   = "tf-import-ecc_nist_p521-${lower(random_id.random.hex)}"
  ecc_secg_p256k1_key_name = "tf-import-ecc_secg_p256k1-${lower(random_id.random.hex)}"
}

resource "ciphertrust_aws_connection" "connection" {
  name = local.connection_name
}

data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.connection.id
}

resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.connection.id
  name           = local.kms_name
  regions        = [data.ciphertrust_aws_account_details.account_details.regions[0]]
}

resource "ciphertrust_aws_key" "aes" {
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  alias                    = [local.aes_key_name]
  import_key_material {
    source_key_name = local.aes_key_name
    source_key_tier = "local"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
}

resource "ciphertrust_aws_key" "hmac_256" {
  alias                    = [local.hmac_key_name]
  customer_master_key_spec = "HMAC_256"
  import_key_material {
    source_key_name = local.hmac_key_name
    source_key_tier = "local"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
}

resource "ciphertrust_aws_key" "rsa_2048" {
  alias                    = [local.rsa_key_name]
  customer_master_key_spec = "RSA_2048"
  import_key_material {
    source_key_name = local.rsa_key_name
    source_key_tier = "local"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
}

resource "ciphertrust_aws_key" "ecc_secg_p256k1" {
  alias                    = [local.ecc_secg_p256k1_key_name]
  customer_master_key_spec = "ECC_SECG_P256K1"
  import_key_material {
    source_key_name = local.ecc_secg_p256k1_key_name
    source_key_tier = "local"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
}

resource "ciphertrust_aws_key" "ecc_nist_p384" {
  alias                    = [local.ecc_nist_p384_key_name]
  customer_master_key_spec = "ECC_NIST_P384"
  import_key_material {
    source_key_name = local.ecc_nist_p384_key_name
    source_key_tier = "local"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
}

resource "ciphertrust_aws_key" "ecc_nist_p521" {
  alias                    = [local.ecc_nist_p521_key_name]
  customer_master_key_spec = "ECC_NIST_P521"
  import_key_material {
    source_key_name = local.ecc_nist_p521_key_name
    source_key_tier = "local"
  }
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
}
