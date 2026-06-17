package cckm

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceAWSXKSKey{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSXKSKey{}
)

func NewDataSourceAWSXKSKeys() datasource.DataSource {
	return &dataSourceAWSXKSKey{}
}

func (d *dataSourceAWSXKSKey) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type dataSourceAWSXKSKey struct {
	client *common.Client
}

func (d *dataSourceAWSXKSKey) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_xks_keys_list"
}

func (d *dataSourceAWSXKSKey) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of AWS XKS keys. " +
			"Supply a 'filters' map of key:value pairs matching the CipherTrust Manager API query parameters " +
			"for listing AWS keys (e.g. region, alias, keyid). " +
			"Use 'limit=-1' to return more than 10 matches.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key:value pairs matching CipherTrust Manager API query parameters for listing AWS XKS keys.",
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "Total number of keys returned by the API for the given filters.",
			},
			"keys": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of AWS XKS keys matching the given filters.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: awsXKSKeyListItemAttributes(),
				},
			},
		},
	}
}

// Read lists AWS XKS keys matching the given filters and populates Terraform state.
func (d *dataSourceAWSXKSKey) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[data_source_aws_xks_key.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[data_source_aws_xks_key.go -> Read]["+id+"]")

	var state AWSXKSKeyListDataSourceTFSDK
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
		msg := "Error listing AWS XKS keys on CipherTrust Manager."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "filters": fmt.Sprintf("%v", filters)})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	resources := gjson.Get(response, "resources").Array()
	state.Keys = make([]AWSXKSKeyDataSourceTFSDK, 0, len(resources))
	for _, keyJSON := range resources {
		var item AWSXKSKeyDataSourceTFSDK
		d.setXKSKeyState(ctx, keyJSON.Raw, &item, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Keys = append(state.Keys, item)
	}
	state.Matched = types.Int64Value(gjson.Get(response, "total").Int())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// setXKSKeyState populates the Terraform data source state for an AWS XKS key from an API response JSON string.
func (d *dataSourceAWSXKSKey) setXKSKeyState(ctx context.Context, response string, plan *AWSXKSKeyDataSourceTFSDK, diags *diag.Diagnostics) {
	setCustomKeyStoreKeyCommonState(ctx, response, &plan.AWSKeyStoreKeyDataSourceCommonTFSDK, diags)
	plan.AWSXKSKeyID = types.StringValue(gjson.Get(response, "aws_param.XksKeyConfiguration.Id").String())
	plan.SourceKeyTier = types.StringValue(gjson.Get(response, "key_source").String())
}

// setCustomKeyStoreKeyCommonState populates the common key store key fields shared by the XKS
// and CloudHSM key data sources. Fields sourced from aws_param are stored exclusively inside
// the aws_param nested block via setKeyStoreDSAwsParam; they are not set at the outer level.
func setCustomKeyStoreKeyCommonState(ctx context.Context, response string, plan *AWSKeyStoreKeyDataSourceCommonTFSDK, diags *diag.Diagnostics) {
	setCommonKeyDataSourceState(ctx, response, &plan.AWSKeyDataSourceCommonTFSDK, diags)
	plan.Blocked = types.BoolValue(gjson.Get(response, "blocked").Bool())
	plan.AWSCustomKeyStoreID = types.StringValue(gjson.Get(response, "aws_param.CustomKeyStoreId").String())
	plan.KMSName = types.StringValue(gjson.Get(response, "kms").String())
	plan.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	plan.CustomKeyStoreID = types.StringValue(gjson.Get(response, "custom_key_store_id").String())
	plan.Linked = types.BoolValue(gjson.Get(response, "linked_state").Bool())
	plan.Region = types.StringValue(gjson.Get(response, "region").String())
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.AWSParam = setKeyStoreDSAwsParam(ctx, response, plan.Linked.ValueBool(), diags)
}

// setKeyStoreDSAwsParam builds the computed-only AWSKeyStoreDSAwsParamTFSDK block from an
// API response JSON string. Alias, description, and tags are only populated for linked keys.
// All other aws_param computed fields are populated regardless of linked state.
func setKeyStoreDSAwsParam(ctx context.Context, response string, linked bool, diags *diag.Diagnostics) *AWSKeyStoreDSAwsParamTFSDK {
	p := &AWSKeyStoreDSAwsParamTFSDK{}
	if linked {
		setAliases(response, &p.Alias, diags)
		setKeyTags(ctx, response, &p.Tags, diags)
	} else {
		var d diag.Diagnostics
		p.Alias, d = types.SetValue(types.StringType, []attr.Value{})
		if d.HasError() {
			diags.Append(d...)
		}
		p.Tags, d = types.MapValueFrom(ctx, types.StringType, map[string]string{})
		if d.HasError() {
			diags.Append(d...)
		}
	}
	p.Description = types.StringValue(gjson.Get(response, "aws_param.Description").String())
	// Computed fields from aws_param populated for all keys.
	p.Arn = types.StringValue(gjson.Get(response, "aws_param.Arn").String())
	p.AWSAccountID = types.StringValue(gjson.Get(response, "aws_param.AWSAccountId").String())
	p.AWSCustomKeyStoreID = types.StringValue(gjson.Get(response, "aws_param.CustomKeyStoreId").String())
	p.CustomerMasterKeySpec = types.StringValue(gjson.Get(response, "aws_param.CustomerMasterKeySpec").String())
	p.CreationDate = types.StringValue(gjson.Get(response, "aws_param.CreationDate").String())
	p.DeletionDate = types.StringValue(gjson.Get(response, "deletion_date").String())
	p.Enabled = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	p.EncryptionAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.EncryptionAlgorithms").Array(), diags)
	p.ExpirationModel = types.StringValue(gjson.Get(response, "aws_param.ExpirationModel").String())
	p.KeyID = types.StringValue(gjson.Get(response, "aws_param.KeyID").String())
	p.KeyManager = types.StringValue(gjson.Get(response, "aws_param.KeyManager").String())
	// key_rotation_enabled is set for CloudHSM keys; XKS keys will return false/zero.
	p.KeyRotationEnabled = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	p.KeyState = types.StringValue(gjson.Get(response, "aws_param.KeyState").String())
	p.KeyUsage = types.StringValue(gjson.Get(response, "aws_param.KeyUsage").String())
	p.MacAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.MacAlgorithmSpec").Array(), diags)
	p.Origin = types.StringValue(gjson.Get(response, "aws_param.Origin").String())
	p.Policy = types.StringValue(gjson.Get(response, "aws_param.Policy").String())
	// xks_key_configuration is set for XKS keys; CloudHSM keys will have an empty JSON string.
	p.XksKeyConfiguration = types.StringValue(gjson.Get(response, "aws_param.XksKeyConfiguration").Raw)
	return p
}
