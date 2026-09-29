package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const azureSubscriptionFiltersTable = "\n\n> **Note:** Although some filters represent integers, " +
	"all filter values must be specified as strings. " +
	"For example, use `\"-1\"` rather than `-1`.\n\n" +
	"| filter         | type    | description |\n" +
	"|----------------|---------|-------------|\n" +
	"| skip           | integer | Index of the first result to return (default: 0). |\n" +
	"| limit          | integer | Max number of results to return (default: 10). Use `\"-1\"` to return all matches. |\n" +
	"| sort           | string  | Field to sort by. Valid values are `subscription_id`, `createdAt`, and `updatedAt`. Prefix with `-` for descending order. |\n" +
	"| id             | string  | Filter by CipherTrust Manager internal resource ID. |\n" +
	"| subscriptionId | string  | Filter by Azure subscription ID. |\n" +
	"| displayName    | string  | Filter by subscription display name. |"

var (
	_ datasource.DataSource                     = &dataSourceAzureSubscriptionList{}
	_ datasource.DataSourceWithConfigure        = &dataSourceAzureSubscriptionList{}
	_ datasource.DataSourceWithConfigValidators = &dataSourceAzureSubscriptionList{}

	azureSubscriptionValidFilterKeys = map[string]struct{}{
		"skip": {}, "limit": {}, "sort": {},
		"id": {}, "subscriptionId": {}, "displayName": {},
	}
)

// ConfigValidators rejects unrecognized filter keys at plan time.
func (d *dataSourceAzureSubscriptionList) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{azureSubscriptionFilterValidator{}}
}

type azureSubscriptionFilterValidator struct{}

func (v azureSubscriptionFilterValidator) Description(_ context.Context) string {
	return "Validates that all filter keys are supported."
}
func (v azureSubscriptionFilterValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v azureSubscriptionFilterValidator) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config models.AzureSubscriptionListTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Filters.IsNull() || config.Filters.IsUnknown() {
		return
	}
	for k := range config.Filters.Elements() {
		if _, ok := azureSubscriptionValidFilterKeys[k]; !ok {
			resp.Diagnostics.AddError(
				"Unrecognized filter key",
				fmt.Sprintf("%q is not a supported filter key for ciphertrust_azure_subscription_list.", k),
			)
		}
	}
}

// NewDataSourceAzureSubscriptionList returns a new instance of the
// ciphertrust_azure_subscription_list data source.
func NewDataSourceAzureSubscriptionList() datasource.DataSource {
	return &dataSourceAzureSubscriptionList{}
}

type dataSourceAzureSubscriptionList struct {
	client *common.Client
}

func (d *dataSourceAzureSubscriptionList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_subscription_list"
}

func (d *dataSourceAzureSubscriptionList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *CipherTrust.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	d.client = client
}

func (d *dataSourceAzureSubscriptionList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of Azure subscriptions stored in the " +
			"CipherTrust Manager database. A subscription is added to the database when an Azure vault " +
			"is registered with CipherTrust Manager and removed when its last vault is deregistered. " +
			"Supply a `filters` map to narrow results. " +
			"Use ciphertrust_azure_subscription_details to query subscriptions live from Azure.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key/value pairs matching CipherTrust Manager API query parameters " +
					"for listing Azure subscriptions." + azureSubscriptionFiltersTable,
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "The total number of records matching the given filters.",
			},
			"subscriptions": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of Azure subscriptions stored in CipherTrust Manager.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager internal resource ID.",
						},
						"uri": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager unique resource URI.",
						},
						"account": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager account that owns this resource.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the subscription was registered in CipherTrust Manager.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the subscription was last updated.",
						},
						"subscription_id": schema.StringAttribute{
							Computed:    true,
							Description: "The Azure subscription ID.",
						},
						"subscription_uri": schema.StringAttribute{
							Computed:    true,
							Description: "The Azure subscription URI.",
						},
						"display_name": schema.StringAttribute{
							Computed:    true,
							Description: "The subscription display name.",
						},
						"state": schema.StringAttribute{
							Computed:    true,
							Description: "The subscription state.",
						},
						"authorization_source": schema.StringAttribute{
							Computed:    true,
							Description: "The authorization source of the request.",
						},
						"tenant_id": schema.StringAttribute{
							Computed:    true,
							Description: "The subscription tenant ID.",
						},
					},
				},
			},
		},
	}
}

// Read lists Azure subscriptions from the CipherTrust Manager database,
// optionally filtered by the key:value pairs in the filters attribute,
// and saves the results to state.
func (d *dataSourceAzureSubscriptionList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_azure_subscription_list.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_azure_subscription_list.go -> Read][" + id + "]")

	var state models.AzureSubscriptionListTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		if val, ok := v.(types.String); ok {
			filters.Add(k, val.ValueString())
		}
	}

	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_AZURE+"/subscriptions", filters)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_subscription_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read Azure subscriptions from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	var page models.AzureSubscriptionDBResourcePageJSON
	err = json.Unmarshal([]byte(jsonStr), &page)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_subscription_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read Azure subscriptions from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	state.Subscriptions = []models.AzureSubscriptionDBTFSDK{}
	for _, sub := range page.Resources {
		entry := models.AzureSubscriptionDBTFSDK{
			ID:                  types.StringValue(sub.ID),
			URI:                 types.StringValue(sub.URI),
			Account:             types.StringValue(sub.Account),
			CreatedAt:           types.StringValue(sub.CreatedAt),
			UpdatedAt:           types.StringValue(sub.UpdatedAt),
			SubscriptionID:      types.StringValue(sub.SubscriptionID),
			SubscriptionURI:     types.StringValue(sub.SubscriptionURI),
			DisplayName:         types.StringValue(sub.DisplayName),
			State:               types.StringValue(sub.State),
			AuthorizationSource: types.StringValue(sub.AuthorizationSource),
			TenantID:            types.StringValue(sub.TenantID),
		}
		state.Subscriptions = append(state.Subscriptions, entry)
	}
	state.Matched = types.Int64Value(page.Total)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
