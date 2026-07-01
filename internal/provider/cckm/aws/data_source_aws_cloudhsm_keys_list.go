package cckm

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceAWSCloudHSMKey{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSCloudHSMKey{}
)

func NewDataSourceAWSCloudHSMKeys() datasource.DataSource {
	return &dataSourceAWSCloudHSMKey{}
}

func (d *dataSourceAWSCloudHSMKey) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type dataSourceAWSCloudHSMKey struct {
	client *common.Client
}

func (d *dataSourceAWSCloudHSMKey) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_cloudhsm_keys_list"
}

func (d *dataSourceAWSCloudHSMKey) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of AWS CloudHSM keys. " +
			"Supply a 'filters' map of key:value pairs matching the CipherTrust Manager API query parameters " +
			"for listing AWS keys (e.g. region, alias, keyid). " +
			"Use 'limit=-1' to return more than 10 matches.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key:value pairs matching CipherTrust Manager API query parameters for listing AWS CloudHSM keys.",
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "Total number of keys returned by the API for the given filters.",
			},
			"keys": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of AWS CloudHSM keys matching the given filters.",
				NestedObject: schema.NestedAttributeObject{
					// CloudHSM keys share the keystore-common attributes; no additional fields.
					Attributes: awsKeyStoreListItemAttributes(),
				},
			},
		},
	}
}

// Read lists AWS CloudHSM keys matching the given filters and populates Terraform state.
func (d *dataSourceAWSCloudHSMKey) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[data_source_aws_cloudhsm_key.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[data_source_aws_cloudhsm_key.go -> Read]["+id+"]")

	var state AWSCloudHSMKeyListDataSourceTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		if sv, ok := v.(types.String); ok {
			filters.Add(k, sv.ValueString())
		}
	}

	response, err := d.client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
	if err != nil {
		msg := "Error listing AWS CloudHSM keys on CipherTrust Manager."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "filters": fmt.Sprintf("%v", filters)})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	resources := gjson.Get(response, "resources").Array()
	state.Keys = make([]AWSCloudHSMKeyDataSourceTFSDK, 0, len(resources))
	for _, keyJSON := range resources {
		var item AWSCloudHSMKeyDataSourceTFSDK
		d.setCloudHSMKeyState(ctx, keyJSON.Raw, &item, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Keys = append(state.Keys, item)
	}
	state.Matched = types.Int64Value(gjson.Get(response, "total").Int())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// setCloudHSMKeyState populates the Terraform data source state for an AWS CloudHSM key from an API response JSON string.
func (d *dataSourceAWSCloudHSMKey) setCloudHSMKeyState(ctx context.Context, response string, plan *AWSCloudHSMKeyDataSourceTFSDK, diags *diag.Diagnostics) {
	setCustomKeyStoreKeyCommonState(ctx, response, &plan.AWSKeyStoreKeyDataSourceCommonTFSDK, diags)
}
