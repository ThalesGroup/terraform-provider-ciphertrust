resource "ciphertrust_scheduler" "key_rotation" {
  cckm_key_rotation_params {
    cloud_name = "AzureCloud"
  }
  name       = "rotation_job_name"
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
}

resource "ciphertrust_scheduler" "key_synchronization" {
  cckm_synchronization_params {
    cloud_name      = "azure"
    synchronize_all = true
  }
  name       = "sync_job_name"
  operation  = "cckm_synchronization"
  run_at     = "0 9 * * fri"
}
