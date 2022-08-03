# A scheduler resource suitable for the rotation of AWS keys
resource "ciphertrust_scheduler" "aws_scheduled_key_rotation" {
  cckm_key_rotation_params {
    cloud_name = "aws"
  }
  name       = "rotation-job-name"
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
}

# An example of attaching the scheduler resource to an AWS key using CipherTrust as the key source
resource "ciphertrust_aws_key" "aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
  enable_rotation {
    disable_encrypt = false
    job_config_id   = ciphertrust_scheduler.aws_scheduled_key_rotation.id
    key_source      = "ciphertrust"
  }
}

# An example of attaching the scheduler resource to an AWS key using a DSM as the key source
resource "ciphertrust_aws_key" "aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
  enable_rotation {
    disable_encrypt = true
    dsm_domain_id   = ciphertrust_dsm_domain.dsm_domain.id
    job_config_id   = ciphertrust_scheduler.aws_scheduled_key_rotation.id
    key_source      = "dsm"
  }
}

# A scheduler resource suitable for the rotation of Azure keys
resource "ciphertrust_scheduler" "azure_scheduled_key_rotation" {
  cckm_key_rotation_params {
    cloud_name = "AzureCloud"
  }
  name       = "rotation-job-name"
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
}

# An example of attaching the scheduler resource to an Azure key using CipherTrust as the key source
resource "ciphertrust_azure_key" "azure_key" {
  name  = "key-name"
  vault = ciphertrust_azure_vault.azure_vault.id
  enable_rotation {
    job_config_id = ciphertrust_scheduler.azure_scheduled_key_rotation.id
    key_source    = "ciphertrust"
  }
}

# An example of attaching the scheduler resource to an Azure key using a DSM as the key source
resource "ciphertrust_azure_key" "azure_key" {
  name  = "key-name"
  vault = ciphertrust_azure_vault.azure_vault.id
  enable_rotation {
    dsm_domain_id = ciphertrust_dsm_domain.dsm_domain.id
    job_config_id = ciphertrust_scheduler.azure_scheduled_key_rotation.id
    key_source    = "dsm"
  }
}

# An example of attaching the scheduler resource to an Azure key using Luna-HSM as the key source
resource "ciphertrust_azure_key" "azure_key" {
  name  = "key-name"
  vault = ciphertrust_azure_vault.azure_vault.id
  enable_rotation {
    hsm_partition_id = ciphertrust_hsm_partition.hsm_partition.id
    job_config_id    = ciphertrust_scheduler.azure_scheduled_key_rotation.id
    key_source       = "hsm-luna"
  }
}

# An example of attaching the scheduler resource to an Azure key using Azure as the key source
resource "ciphertrust_azure_key" "azure_key" {
  name  = "key-name"
  vault = ciphertrust_azure_vault.azure_vault.id
  enable_rotation {
    job_config_id = ciphertrust_scheduler.azure_scheduled_key_rotation.id
    key_source    = "native"
  }
}

# A scheduler resource suitable for the rotation of Google cloud keys
resource "ciphertrust_scheduler" "gcp_scheduled_key_rotation" {
  cckm_key_rotation_params {
    cloud_name = "gcp"
  }
  name       = "rotation-job-name"
  operation  = "cckm_key_rotation"
  run_at     = "0 9 * * sat"
}

# An example of attaching the scheduler resource to a Google cloud key using CipherTrust as the key source
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA512"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
  enable_rotation {
    job_config_id = ciphertrust_scheduler.gcp_scheduled_key_rotation.id
    key_source    = "ciphertrust"
  }
}

# An example of attaching the scheduler resource to a Google cloud key using a DSM as the key source
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA512"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
  enable_rotation {
    dsm_domain_id = ciphertrust_dsm_domain.dsm_domain.id
    job_config_id = ciphertrust_scheduler.gcp_scheduled_key_rotation.id
    key_source    = "dsm"
  }
}

# An example of attaching the scheduler resource to a Google cloud key using Luna-HSM as the key source
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA512"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
  enable_rotation {
    job_config_id = ciphertrust_scheduler.gcp_scheduled_key_rotation.id
    hsm_partition_id = ciphertrust_hsm_partition.hsm_partition.id
  }
}

# An example of attaching the scheduler resource to a Google cloud key using Google cloud as the key source
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA512"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
  enable_rotation {
    job_config_id = ciphertrust_scheduler.gcp_scheduled_key_rotation.id
    key_source    = "native"
  }
}

# A scheduler resource for synchronizing AWS keys with CipherTrust Manager
resource "ciphertrust_scheduler" "aws_key_sync" {
  cckm_synchronization_params {
    cloud_name      = "AzureCloud"
    synchronize_all = true
  }
  name       = "sync-job-name"
  operation  = "cckm_synchronization"
  run_at     = "0 9 * * fri"
}

# A scheduler resource for synchronizing Azure keys with CipherTrust Manager
resource "ciphertrust_scheduler" "azure_key_sync" {
  cckm_synchronization_params {
    cloud_name      = "aws"
    synchronize_all = true
  }
  name       = "sync-job-name"
  operation  = "cckm_synchronization"
  run_at     = "0 9 * * fri"
}

# A scheduler suitable for synchronizing Google cloud keys with CipherTrust Manager
resource "ciphertrust_scheduler" "gcp_key_sync" {
  cckm_synchronization_params {
    cloud_name      = "gcp"
    synchronize_all = true
  }
  name       = "sync-job-name"
  operation  = "cckm_synchronization"
  run_at     = "0 9 * * fri"
}
