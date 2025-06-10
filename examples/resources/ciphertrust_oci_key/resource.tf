resource "ciphertrust_oci_key" "test_key" {
  # Required parameters
  name  = "key-name"
  vault = "vault-id"
  oci_key_params = {
    algorithm       = "AES"
    compartment_id  = "compartment-ocid"
    length          = 32
    protection_mode = "SOFTWARE"
    # Optional oci_key_params
    defined_tags = [
      {
        tag = "oci-namespace"
        values = {
          key-tag = "key-value"
        }
      }
    ]
    freeform_tags = {
      key-tag = "key-value"
    }
  }
  # Optional parameters
  enable_auto_rotation = {
    job_config_id = "ciphertrust.scheduler.scheduled.rotation_job.id"
    key_source    = "ciphertrust"
  }
  enable_key                 = true
  curve_id                   = "required for ECDSA keys"
  schedule_for_deletion_days = 14
}
