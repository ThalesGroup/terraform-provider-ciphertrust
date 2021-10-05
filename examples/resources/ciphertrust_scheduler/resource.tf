resource "ciphertrust_scheduler" "rotation_job" {
  key_rotation_params {
    cloud_name = "AzureCloud"
  }
  name       = "job_name"
  run_at     = "0 9 * * sat"
}

