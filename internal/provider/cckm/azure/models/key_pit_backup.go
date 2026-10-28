package models

import "github.com/hashicorp/terraform-plugin-framework/types"

// AzureKeyPitBackupTFSDK is the Terraform state for the ciphertrust_azure_key_pit_backup resource.
type AzureKeyPitBackupTFSDK struct {
	ID               types.String `tfsdk:"id"`
	KeyID            types.String `tfsdk:"key_id"`
	Trigger          types.String `tfsdk:"trigger"`
	Name             types.String `tfsdk:"name"`
	Description      types.String `tfsdk:"description"`
	URI              types.String `tfsdk:"uri"`
	Account          types.String `tfsdk:"account"`
	Tenant           types.String `tfsdk:"tenant"`
	Type             types.String `tfsdk:"type"`
	Backup           types.String `tfsdk:"backup"`
	KeyName          types.String `tfsdk:"key_name"`
	KeyVault         types.String `tfsdk:"key_vault"`
	VaultName        types.String `tfsdk:"vault_name"`
	SubscriptionID   types.String `tfsdk:"subscription_id"`
	SubscriptionName types.String `tfsdk:"subscription_name"`
	Region           types.String `tfsdk:"region"`
	CloudName        types.String `tfsdk:"cloud_name"`
	Gone             types.Bool   `tfsdk:"gone"`
	CreatedAt        types.String `tfsdk:"created_at"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
}
