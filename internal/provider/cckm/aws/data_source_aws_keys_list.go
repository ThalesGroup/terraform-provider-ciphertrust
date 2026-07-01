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
	_ datasource.DataSource              = &dataSourceAWSKey{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSKey{}
)

func NewDataSourceAWSKeys() datasource.DataSource {
	return &dataSourceAWSKey{}
}

func (d *dataSourceAWSKey) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type dataSourceAWSKey struct {
	client *common.Client
}

func (d *dataSourceAWSKey) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_keys_list"
}

func (d *dataSourceAWSKey) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of AWS keys. " +
			"Supply a 'filters' map of key:value pairs matching the CipherTrust Manager API query parameters " +
			"for listing AWS keys (e.g. region, alias, keyid). " +
			"Use 'limit=-1' to return more than 10 matches.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key:value pairs matching CipherTrust Manager API query parameters for listing AWS keys.",
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "Total number of keys returned by the API for the given filters.",
			},
			"keys": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of AWS keys matching the given filters.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: awsKeyListItemAttributes(),
				},
			},
		},
	}
}

// Read lists AWS keys matching the given filters and populates Terraform state.
func (d *dataSourceAWSKey) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[data_source_aws_key.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[data_source_aws_key.go -> Read]["+id+"]")

	var state AWSKeyListDataSourceTFSDK
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
		msg := "Error listing AWS keys on CipherTrust Manager."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "filters": fmt.Sprintf("%v", filters)})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	resources := gjson.Get(response, "resources").Array()
	state.Keys = make([]AWSKeyDataSourceTFSDK, 0, len(resources))
	for _, keyJSON := range resources {
		var item AWSKeyDataSourceTFSDK
		d.setKeyDataSourceState(ctx, keyJSON.Raw, &item, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		kid := gjson.Get(keyJSON.Raw, "aws_param.KeyID").String()
		region := gjson.Get(keyJSON.Raw, "region").String()
		item.Region = types.StringValue(region)
		item.ID = types.StringValue(region + "\\" + kid)
		state.Keys = append(state.Keys, item)
	}
	state.Matched = types.Int64Value(gjson.Get(response, "total").Int())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// setKeyDataSourceState populates the full Terraform data source state for an AWS key from an API response JSON string.
// Fields sourced from aws_param (alias, tags, description, arn, key_state, etc.) are stored
// exclusively inside the aws_param nested block via setKeyDSAwsParam; they are NOT set at the
// outer level.
func (d *dataSourceAWSKey) setKeyDataSourceState(ctx context.Context, response string, state *AWSKeyDataSourceTFSDK, diags *diag.Diagnostics) {
	setCommonKeyDataSourceState(ctx, response, &state.AWSKeyDataSourceCommonTFSDK, diags)
	state.AutoRotate = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	state.AutoRotationPeriodInDays = types.Int64Value(gjson.Get(response, "aws_param.RotationPeriodInDays").Int())
	state.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	state.KMSName = types.StringValue(gjson.Get(response, "kms").String())
	state.MultiRegion = types.BoolValue(gjson.Get(response, "aws_param.MultiRegion").Bool())
	state.MultiRegionConfiguration = setMultiRegionConfig(response, diags)
	state.NextRotationDate = types.StringValue(gjson.Get(response, "aws_param.NextRotationDate").String())
	state.AWSParam = setKeyDSAwsParam(ctx, response, diags)
}

// setKeyDSAwsParam builds the computed-only AWSKeyDSAwsParamTFSDK block from an API response JSON string.
// It covers all AWS key types since there is a single datasource for all types.
func setKeyDSAwsParam(ctx context.Context, response string, diags *diag.Diagnostics) *AWSKeyDSAwsParamTFSDK {
	p := &AWSKeyDSAwsParamTFSDK{}
	setAliases(response, &p.Alias, diags)
	p.Arn = types.StringValue(gjson.Get(response, "aws_param.Arn").String())
	p.AWSCustomKeyStoreID = types.StringValue(gjson.Get(response, "aws_param.CustomKeyStoreId").String())
	p.CreationDate = types.StringValue(gjson.Get(response, "aws_param.CreationDate").String())
	p.CurrentKeyMaterialID = types.StringValue(gjson.Get(response, "aws_param.CurrentKeyMaterialId").String())
	p.CustomerMasterKeySpec = types.StringValue(gjson.Get(response, "aws_param.CustomerMasterKeySpec").String())
	p.DeletionDate = types.StringValue(gjson.Get(response, "deletion_date").String())
	p.Description = types.StringValue(gjson.Get(response, "aws_param.Description").String())
	p.Enabled = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	p.EncryptionAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.EncryptionAlgorithms").Array(), diags)
	p.ExpirationModel = types.StringValue(gjson.Get(response, "aws_param.ExpirationModel").String())
	p.KeyID = types.StringValue(gjson.Get(response, "aws_param.KeyID").String())
	p.KeyManager = types.StringValue(gjson.Get(response, "aws_param.KeyManager").String())
	p.KeyRotationEnabled = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	p.KeyState = types.StringValue(gjson.Get(response, "aws_param.KeyState").String())
	p.KeyUsage = types.StringValue(gjson.Get(response, "aws_param.KeyUsage").String())
	p.MacAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.MacAlgorithmSpec").Array(), diags)
	p.MultiRegion = types.BoolValue(gjson.Get(response, "aws_param.MultiRegion").Bool())
	p.MultiRegionConfiguration = setMultiRegionConfig(response, diags)
	p.NextRotationDate = types.StringValue(gjson.Get(response, "aws_param.NextRotationDate").String())
	p.Origin = types.StringValue(gjson.Get(response, "aws_param.Origin").String())
	p.Policy = types.StringValue(gjson.Get(response, "aws_param.Policy").String())
	p.ReplicaPolicy = types.StringValue(gjson.Get(response, "aws_param.ReplicaPolicy").String())
	p.ReplicaTags = types.StringValue(gjson.Get(response, "aws_param.ReplicaTags").Raw)
	if v := gjson.Get(response, "aws_param.RotationPeriodInDays"); v.Exists() {
		p.RotationPeriodInDays = types.Int64Value(v.Int())
	} else {
		p.RotationPeriodInDays = types.Int64Null()
	}
	setKeyTags(ctx, response, &p.Tags, diags)
	p.ValidTo = types.StringValue(gjson.Get(response, "aws_param.ValidTo").String())
	p.XksKeyConfiguration = types.StringValue(gjson.Get(response, "aws_param.XksKeyConfiguration").Raw)
	return p
}

// setCommonKeyDataSourceState populates the non-aws_param fields shared across all three
// AWS key list datasource item types. Fields sourced from the API aws_param block are NOT set here;
// each datasource sets them exclusively inside its own aws_param nested block.
func setCommonKeyDataSourceState(ctx context.Context, response string, state *AWSKeyDataSourceCommonTFSDK, diags *diag.Diagnostics) {
	state.KeyID = types.StringValue(gjson.Get(response, "id").String())
	state.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.ExternalAccounts = utils.StringSliceJSONToSetValue(gjson.Get(response, "external_accounts").Array(), diags)
	state.KeyAdmins = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_admins").Array(), diags)
	state.KeyAdminsRoles = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_admins_roles").Array(), diags)
	state.KeyMaterialOrigin = types.StringValue(gjson.Get(response, "key_material_origin").String())
	state.KeySource = types.StringValue(gjson.Get(response, "key_source").String())
	state.KeyType = types.StringValue(gjson.Get(response, "key_type").String())
	state.KeyUsers = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_users").Array(), diags)
	state.KeyUsersRoles = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_users_roles").Array(), diags)
	setKeyLabels(ctx, response, state.KeyID.ValueString(), &state.Labels, diags)
	state.LocalKeyID = types.StringValue(gjson.Get(response, "local_key_id").String())
	state.LocalKeyName = types.StringValue(gjson.Get(response, "local_key_name").String())
	setPolicyTemplateTag(ctx, response, &state.PolicyTemplateTag, diags)
	state.RotatedAt = types.StringValue(gjson.Get(response, "rotated_at").String())
	state.RotatedFrom = types.StringValue(gjson.Get(response, "rotated_from").String())
	state.RotationStatus = types.StringValue(gjson.Get(response, "rotation_status").String())
	state.RotatedTo = types.StringValue(gjson.Get(response, "rotated_to").String())
	state.SyncedAt = types.StringValue(gjson.Get(response, "synced_at").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
}
