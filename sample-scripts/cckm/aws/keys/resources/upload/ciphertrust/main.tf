terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.1"
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
  connection_id = ciphertrust_aws_connection.aws_connection.id
}

resource "ciphertrust_aws_kms" "kms" {
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.aws_connection.id
  name          = local.kms_name
  regions       = data.ciphertrust_aws_account_details.account_details.regions
}

resource "ciphertrust_cm_key" "aes" {
  name      = local.aes_key_name
  algorithm = "AES"
}

resource "ciphertrust_aws_byok_key" "aes" {
  kms_id                = ciphertrust_aws_kms.kms.id
  region                = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier = ciphertrust_cm_key.aes.id
  source_key_tier       = "local"
  aws_param = {
    alias                    = ["aws-aes-key-upload-${lower(random_id.random.hex)}"]
    customer_master_key_spec = "SYMMETRIC_DEFAULT"
    key_usage                = "ENCRYPT_DECRYPT"
  }
}

resource "ciphertrust_cm_key" "hmac_sha256" {
  name      = local.hmac_key_name
  algorithm = "hmac-sha256"
  key_size  = 256
}

resource "ciphertrust_aws_byok_key" "hmac_256" {
  kms_id                = ciphertrust_aws_kms.kms.id
  region                = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier = ciphertrust_cm_key.hmac_sha256.id
  source_key_tier       = "local"
  aws_param = {
    alias                    = [local.hmac_key_name]
    customer_master_key_spec = "HMAC_256"
    key_usage                = "GENERATE_VERIFY_MAC"
  }
}

resource "ciphertrust_cm_key" "rsa" {
  name      = local.rsa_key_name
  algorithm = "RSA"
  key_size  = 2048
}

resource "ciphertrust_aws_byok_key" "rsa" {
  kms_id                = ciphertrust_aws_kms.kms.id
  region                = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier = ciphertrust_cm_key.rsa.id
  source_key_tier       = "local"
  aws_param = {
    alias                    = [local.rsa_key_name]
    customer_master_key_spec = "RSA_2048"
    key_usage                = "ENCRYPT_DECRYPT"
  }
}

resource "ciphertrust_cm_key" "secp256k1" {
  name      = local.ecc_secg_p256k1_key_name
  algorithm = "EC"
  curveid   = "secp256k1"
}

resource "ciphertrust_aws_byok_key" "ecc_secg_p256k1" {
  kms_id                = ciphertrust_aws_kms.kms.id
  region                = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier = ciphertrust_cm_key.secp256k1.id
  source_key_tier       = "local"
  aws_param = {
    alias                    = [local.ecc_secg_p256k1_key_name]
    customer_master_key_spec = "ECC_SECG_P256K1"
    key_usage                = "SIGN_VERIFY"
  }
}

resource "ciphertrust_cm_key" "secp384r1" {
  name      = local.ecc_nist_p384_key_name
  algorithm = "EC"
  curveid   = "secp384r1"
}

resource "ciphertrust_aws_byok_key" "ecc_nist_p384" {
  kms_id                = ciphertrust_aws_kms.kms.id
  region                = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier = ciphertrust_cm_key.secp384r1.id
  source_key_tier       = "local"
  aws_param = {
    alias                    = ["aws-ECC_NIST_P384-upload-${lower(random_id.random.hex)}"]
    customer_master_key_spec = "ECC_NIST_P384"
    key_usage                = "SIGN_VERIFY"
  }
}

resource "ciphertrust_cm_key" "secp521r1" {
  name      = local.ecc_nist_p521_key_name
  algorithm = "EC"
  curveid   = "secp521r1"
}

resource "ciphertrust_aws_byok_key" "ecc_nist_p521" {
  kms_id                = ciphertrust_aws_kms.kms.id
  region                = ciphertrust_aws_kms.kms.regions[0]
  source_key_identifier = ciphertrust_cm_key.secp521r1.id
  source_key_tier       = "local"
  aws_param = {
    alias                    = [local.ecc_nist_p521_key_name]
    customer_master_key_spec = "ECC_NIST_P521"
    key_usage                = "SIGN_VERIFY"
  }
}
