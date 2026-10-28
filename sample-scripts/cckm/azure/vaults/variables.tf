variable "azure_client_id" {
  description = "Azure application (client) ID."
  type        = string
}

variable "azure_tenant_id" {
  description = "Azure tenant ID."
  type        = string
}

variable "azure_client_secret" {
  description = "Azure application client secret."
  type        = string
  sensitive   = true
}

variable "azure_non_purgeable_vault" {
  description = "Name of an existing Azure Key Vault that the connection can access."
  type        = string
}
