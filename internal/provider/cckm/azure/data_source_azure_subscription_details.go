package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &dataSourceAzureSubscriptionDetails{}
	_ datasource.DataSourceWithConfigure = &dataSourceAzureSubscriptionDetails{}
)

// NewDataSourceAzureSubscriptionDetails returns a new instance of the
// ciphertrust_azure_subscription_details data source.
func NewDataSourceAzureSubscriptionDetails() datasource.DataSource {
	return &dataSourceAzureSubscriptionDetails{}
}

type dataSourceAzureSubscriptionDetails struct {
	client *common.Client
}

func (d *dataSourceAzureSubscriptionDetails) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *dataSourceAzureSubscriptionDetails) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_subscription_details"
}

func (d *dataSourceAzureSubscriptionDetails) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve Azure subscription details directly from Azure " +
			"via a CipherTrust Manager Azure connection. The subscriptions returned are fetched live " +
			"from Azure and are not stored in the CipherTrust Manager database. " +
			"Use ciphertrust_azure_subscription_list to query subscriptions already added to CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager Azure connection name or ID.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
			},
			"subscriptions": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of Azure subscriptions available to the connection.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"subscription_id": schema.StringAttribute{
							Computed:    true,
							Description: "The Azure subscription ID",
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
						"subscription_policies": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Subscription policies for this subscription.",
							Attributes: map[string]schema.Attribute{
								"location_placement_id": schema.StringAttribute{
									Computed:    true,
									Description: "The subscription location placement ID.",
								},
								"quota_id": schema.StringAttribute{
									Computed:    true,
									Description: "The subscription quota ID.",
								},
								"spending_limit": schema.StringAttribute{
									Computed:    true,
									Description: "The subscription spending limit.",
								},
							},
						},
					},
				},
			},
		},
	}
}

// Read retrieves all Azure subscriptions available to the given connection and
// saves them to state.
func (d *dataSourceAzureSubscriptionDetails) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_azure_subscription_details.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_azure_subscription_details.go -> Read][" + id + "]")

	var state models.AzureSubscriptionDetailsTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := models.AzureSubscriptionInputJSON{
		Connection: state.ConnectionID.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error reading Azure subscription details, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection": payload.Connection})
		d.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	response, err := d.client.PostDataV2(ctx, id, common.URL_AZURE+"/get-subscriptions", payloadJSON)
	if err != nil {
		msg := "Error reading Azure subscription details."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection": payload.Connection})
		d.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	var subs []models.SubscriptionModelJSON
	err = json.Unmarshal([]byte(response), &subs)
	if err != nil {
		msg := "Error reading Azure subscription details, invalid data output."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection": payload.Connection})
		d.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	state.Subscriptions = []models.AzureSubscriptionTFSDK{}
	for _, sub := range subs {
		policies := models.SubscriptionPoliciesTFSDK{
			LocationPlacementID: types.StringNull(),
			QuotaID:             types.StringNull(),
			SpendingLimit:       types.StringNull(),
		}
		if sub.SubscriptionPolicies != nil {
			policies = models.SubscriptionPoliciesTFSDK{
				LocationPlacementID: types.StringPointerValue(sub.SubscriptionPolicies.LocationPlacementID),
				QuotaID:             types.StringPointerValue(sub.SubscriptionPolicies.QuotaID),
				SpendingLimit:       types.StringPointerValue(sub.SubscriptionPolicies.SpendingLimit),
			}
		}
		entry := models.AzureSubscriptionTFSDK{
			SubscriptionID:       types.StringPointerValue(sub.SubscriptionID),
			DisplayName:          types.StringPointerValue(sub.DisplayName),
			State:                types.StringPointerValue(sub.State),
			AuthorizationSource:  types.StringPointerValue(sub.AuthorizationSource),
			TenantID:             types.StringPointerValue(sub.TenantID),
			SubscriptionPolicies: policies,
		}
		state.Subscriptions = append(state.Subscriptions, entry)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
