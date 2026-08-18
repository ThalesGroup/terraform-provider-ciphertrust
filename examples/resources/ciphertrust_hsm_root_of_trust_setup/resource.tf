# Terraform Configuration for CipherTrust Provider

# These configurations demonstrate the creation of an HSM Root of trust setup for types "luna", "lunapci" and "lunatct"
# with the CipherTrust provider. Only one HSM root of trust setup can exist on a given
# CipherTrust Manager at a time — the four resources below are alternative examples for
# different HSM types, not meant to be applied together. Keep only the one that matches
# your target HSM type and delete the others.
#
# WARNING: Create() resets the appliance and wipes all existing CipherTrust Manager data,
# and Delete() always performs a full appliance wipe regardless of the 'reset'/'delay'
# values used at creation. Never apply this against a shared or production instance.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.1"
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

# An example of HSM root of trust setup of type luna
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup_luna" {
  type = "luna"
  conn_info = {
    partition_name     = "kylo-partition"
    partition_password = "sOmeP@ssword"
  }
  initial_config = {
    host            = "10.10.10.10"
    serial          = "1234"
    server-cert     = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert     = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert-key = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
  }
  reset = true
  delay = 5
}

# An example of HSM root of trust setup of type Luna Network HSM using the STC protocol
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup_luna_stc" {
  type = "luna"
  conn_info = {
    partition_name     = "kylo-partition"
    partition_password = "sOmeP@ssword"
  }
  initial_config = {
    host             = "10.10.10.10"
    serial           = "1234"
    server-cert      = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    stc-par-identity = "VGhpcyBpcyB0aGUgZXhhbXB...sZSBvZiBzdGMtcGFyLWlkZW50aXR5"
  }
  reset = true
  delay = 5
}

# An example of HSM root of trust setup of type lunapci
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup_lunapci" {
  type = "lunapci"
  conn_info = {
    partition_name     = "kylo-partition"
    partition_password = "sOmeP@ssword"
  }
  reset = true
  delay = 5
}

# An example of HSM root of trust setup of type lunatct
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup_lunatct" {
  type = "lunatct"
  conn_info = {
    partition_name     = "kylo-partition"
    partition_password = "sOmeP@ssword"
  }
  initial_config = {
    host            = "10.10.10.10"
    serial          = "1234"
    server-cert     = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert     = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert-key = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
  }
  reset = true
  delay = 5
}
