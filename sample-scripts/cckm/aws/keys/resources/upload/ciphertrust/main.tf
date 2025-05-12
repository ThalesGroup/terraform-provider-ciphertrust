terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.9.0-beta4"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name          = "tf-upload-${lower(random_id.random.hex)}"
  kms_name                 = "tf-upload-${lower(random_id.random.hex)}"
  aes_key_name             = "tf-upload-aes-${lower(random_id.random.hex)}"
  rsa_key_name             = "tf-upload-rsa-${lower(random_id.random.hex)}"
  ecc_nist_p384_key_name   = "tf-upload-ecc_nist_p384-${lower(random_id.random.hex)}"
  ecc_nist_p521_key_name   = "tf-upload-ecc_nist_p521-${lower(random_id.random.hex)}"
  ecc_secg_p256k1_key_name = "tf-upload-ecc_secg_p256k1-${lower(random_id.random.hex)}"
  hmac_key_name            = "tf-upload-hmac_key_name-${lower(random_id.random.hex)}"
}

resource "ciphertrust_aws_connection" "aws_connection" {
  name = local.connection_name
}

data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws_connection.id
}

resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = local.kms_name
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

resource "ciphertrust_cm_key" "aes" {
  name      = local.aes_key_name
  algorithm = "AES"
}

resource "ciphertrust_aws_key" "aes" {
  alias                    = ["aws-aes-key-upload-${lower(random_id.random.hex)}"]
  kms                      = ciphertrust_aws_kms.kms.id
  region                   = ciphertrust_aws_kms.kms.regions[0]
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.aes.id
  }
}

resource "ciphertrust_cm_key" "hmac_sha256" {
  name      = local.hmac_key_name
  algorithm = "hmac-sha256"
  key_size  = "256"
}

resource "ciphertrust_aws_key" "hmac_256" {
  alias                    = [local.hmac_key_name]
  kms                      = ciphertrust_aws_kms.kms.id
  region                   = ciphertrust_aws_kms.kms.regions[0]
  customer_master_key_spec = "HMAC_256"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.hmac_sha256.id
  }
}

resource "ciphertrust_cm_key" "rsa" {
  name      = local.rsa_key_name
  algorithm = "RSA"
  key_size  = 2048
}

resource "ciphertrust_aws_key" "rsa" {
  alias                    = [local.rsa_key_name]
  kms                      = ciphertrust_aws_kms.kms.id
  region                   = ciphertrust_aws_kms.kms.regions[0]
  customer_master_key_spec = "RSA_2048"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.rsa.id
  }
}

resource "ciphertrust_cm_key" "secp256k1" {
  name      = local.ecc_secg_p256k1_key_name
  algorithm = "EC"
  curveid   = "secp256k1"
}

resource "ciphertrust_aws_key" "ecc_secg_p256k1" {
  alias                    = [local.ecc_secg_p256k1_key_name]
  kms                      = ciphertrust_aws_kms.kms.id
  region                   = ciphertrust_aws_kms.kms.regions[0]
  customer_master_key_spec = "ECC_SECG_P256K1"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.secp256k1.id
  }
}

resource "ciphertrust_cm_key" "secp384r1" {
  name      = local.ecc_nist_p384_key_name
  algorithm = "EC"
  curveid   = "secp384r1"
}

resource "ciphertrust_aws_key" "ecc_nist_p384" {
  alias                    = ["aws-ECC_NIST_P384-upload-${lower(random_id.random.hex)}"]
  kms                      = ciphertrust_aws_kms.kms.id
  region                   = ciphertrust_aws_kms.kms.regions[0]
  customer_master_key_spec = "ECC_NIST_P384"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.secp384r1.id
  }
}

resource "ciphertrust_cm_key" "secp521r1" {
  name      = local.ecc_nist_p521_key_name
  algorithm = "EC"
  curveid   = "secp521r1"
}

resource "ciphertrust_aws_key" "ecc_nist_p521" {
  alias                    = [local.ecc_nist_p521_key_name]
  kms                      = ciphertrust_aws_kms.kms.id
  region                   = ciphertrust_aws_kms.kms.regions[0]
  customer_master_key_spec = "ECC_NIST_P521"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.secp521r1.id
  }
}
