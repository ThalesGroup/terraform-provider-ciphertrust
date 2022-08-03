variable "vault_name" {
  type    = string
  default = "vault-name"
}
variable "vault_resource_group_name" {
  type    = string
  default = "resource-group"
}
# Set this to the location of the vault
variable "resource_group_location" {
  type    = string
  default = "resource-group-location"
}
