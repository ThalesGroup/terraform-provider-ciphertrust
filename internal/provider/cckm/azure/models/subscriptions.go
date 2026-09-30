package models

import "github.com/hashicorp/terraform-plugin-framework/types"

// --- Types for ciphertrust_azure_subscription_details (POST get-subscriptions) ---

// AzureSubscriptionInputJSON is the request body for the get-subscriptions API.
type AzureSubscriptionInputJSON struct {
	Connection string `json:"connection"`
}

// SubscriptionPoliciesJSON maps the Azure subscription policies object returned
// by the get-subscriptions API.
type SubscriptionPoliciesJSON struct {
	// LocationPlacementID indicates which regions are visible for the subscription.
	LocationPlacementID *string `json:"locationPlacementId,omitempty"`
	// QuotaID is the subscription quota ID.
	QuotaID *string `json:"quotaId,omitempty"`
	// SpendingLimit is the subscription spending limit ("On", "Off", or "CurrentPeriodOff").
	SpendingLimit *string `json:"spendingLimit,omitempty"`
}

// SubscriptionModelJSON is one entry in the []SubModel array returned by
// the get-subscriptions API.
type SubscriptionModelJSON struct {
	ID                   *string                   `json:"id,omitempty"`
	SubscriptionID       *string                   `json:"subscriptionId,omitempty"`
	DisplayName          *string                   `json:"displayName,omitempty"`
	State                *string                   `json:"state,omitempty"`
	SubscriptionPolicies *SubscriptionPoliciesJSON `json:"subscriptionPolicies,omitempty"`
	AuthorizationSource  *string                   `json:"authorizationSource,omitempty"`
	TenantID             *string                   `json:"tenantId,omitempty"`
}

// SubscriptionPoliciesTFSDK is the Terraform state for the subscription_policies
// nested attribute.
type SubscriptionPoliciesTFSDK struct {
	LocationPlacementID types.String `tfsdk:"location_placement_id"`
	QuotaID             types.String `tfsdk:"quota_id"`
	SpendingLimit       types.String `tfsdk:"spending_limit"`
}

// AzureSubscriptionTFSDK is the Terraform state for a single Azure subscription
// entry in the ciphertrust_azure_subscription_details data source.
type AzureSubscriptionTFSDK struct {
	SubscriptionID       types.String              `tfsdk:"subscription_id"`
	DisplayName          types.String              `tfsdk:"display_name"`
	State                types.String              `tfsdk:"state"`
	AuthorizationSource  types.String              `tfsdk:"authorization_source"`
	TenantID             types.String              `tfsdk:"tenant_id"`
	SubscriptionPolicies SubscriptionPoliciesTFSDK `tfsdk:"subscription_policies"`
}

// AzureSubscriptionDetailsTFSDK is the top-level Terraform state for the
// ciphertrust_azure_subscription_details data source.
type AzureSubscriptionDetailsTFSDK struct {
	ConnectionID  types.String             `tfsdk:"connection_id"`
	Subscriptions []AzureSubscriptionTFSDK `tfsdk:"subscriptions"`
}

// --- Types for ciphertrust_azure_subscription_list (GET subscriptions from CCKM DB) ---

// AzureSubscriptionDBJSON is the JSON shape of one subscription record in the
// resources array returned by the GET /subscriptions list API.
// Field names follow the JSON tags on navic's Subscription model.
type AzureSubscriptionDBJSON struct {
	ID                  string `json:"id"`
	URI                 string `json:"uri"`
	Account             string `json:"account"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
	SubscriptionID      string `json:"subscriptionId"`
	SubscriptionURI     string `json:"subscriptionUri"`
	DisplayName         string `json:"displayName,omitempty"`
	State               string `json:"state,omitempty"`
	AuthorizationSource string `json:"authorizationSource,omitempty"`
	TenantID            string `json:"tenantId,omitempty"`
}

// AzureSubscriptionDBResourcePageJSON is the page envelope returned by
// ListWithFilters for the GET /subscriptions endpoint.
type AzureSubscriptionDBResourcePageJSON struct {
	Total     int64                     `json:"total"`
	Resources []AzureSubscriptionDBJSON `json:"resources"`
}

// AzureSubscriptionDBTFSDK is the Terraform state for one subscription entry
// in the ciphertrust_azure_subscription_list data source.
type AzureSubscriptionDBTFSDK struct {
	ID                  types.String `tfsdk:"id"`
	URI                 types.String `tfsdk:"uri"`
	Account             types.String `tfsdk:"account"`
	CreatedAt           types.String `tfsdk:"created_at"`
	UpdatedAt           types.String `tfsdk:"updated_at"`
	SubscriptionID      types.String `tfsdk:"subscription_id"`
	SubscriptionURI     types.String `tfsdk:"subscription_uri"`
	DisplayName         types.String `tfsdk:"display_name"`
	State               types.String `tfsdk:"state"`
	AuthorizationSource types.String `tfsdk:"authorization_source"`
	TenantID            types.String `tfsdk:"tenant_id"`
}

// AzureSubscriptionListTFSDK is the top-level Terraform state for the
// ciphertrust_azure_subscription_list data source.
type AzureSubscriptionListTFSDK struct {
	Filters       types.Map                  `tfsdk:"filters"`
	Matched       types.Int64                `tfsdk:"matched"`
	Subscriptions []AzureSubscriptionDBTFSDK `tfsdk:"subscriptions"`
}
