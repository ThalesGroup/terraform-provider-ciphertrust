package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceAWSKey{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSKey{}
)

func NewDataSourceAWSKms() datasource.DataSource {
	return &dataSourceAWSKms{}
}

func (d *dataSourceAWSKms) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type dataSourceAWSKms struct {
	client *common.Client
}

type AWSKmsDataSourceModel struct {
	Filters types.Map       `tfsdk:"filters"`
	Matched types.Int64     `tfsdk:"matched"`
	Kmses   []KMSModelTFSDK `tfsdk:"kms"`
}

func (d *dataSourceAWSKms) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_kms_list"
}

func (d *dataSourceAWSKms) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of CipherTrust Manager AWS KMS resources.\n\n" +
			"Give a filter of 'limit=-1' to list all KMS resources that match the filter. Default is 10 matches.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A list of key:value pairs where the 'key' is any of the filters available in CipherTrust Manager's API playground for listing CipherTrust Manager AWS KMS resources.",
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "The number of vaults which matched the filters.",
			},
			"kms": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"account": schema.StringAttribute{
							Description: "The account which owns this resource.",
							Computed:    true,
						},
						"account_id": schema.StringAttribute{
							Computed:    true,
							Description: "ID of the AWS account.",
						},
						"acls": schema.SetNestedAttribute{
							Computed:    true,
							Description: "List of ACLs that have been added to the KMS.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"actions": schema.SetAttribute{
										Computed:    true,
										Description: "Permitted actions.",
										ElementType: types.StringType,
									},
									"group": schema.StringAttribute{
										Computed:    true,
										Description: "CipherTrust Manager group.",
									},
									"user_id": schema.StringAttribute{
										Computed:    true,
										Description: "CipherTrust Manager user ID.",
									},
								},
							},
						},
						"application": schema.StringAttribute{
							Description: "The application this resource belongs to.",
							Computed:    true,
						},
						"arn": schema.StringAttribute{
							Computed:    true,
							Description: "Amazon Resource Name.",
						},
						"assume_role_arn": schema.StringAttribute{
							Optional:    true,
							Description: "Amazon Resource Name (ARN) of the role to be assumed.",
						},
						"assume_role_external_id": schema.StringAttribute{
							Optional:    true,
							Description: "External ID for the role to be assumed. This parameter can be specified only with \"assume_role_arn\".",
						},
						"auto_added": schema.BoolAttribute{
							Computed:    true,
							Description: "True if the KMS was added by a scheduler.",
						},
						"aws_connection": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager resource ID of the connection which manages this account.",
						},
						"created_at": schema.StringAttribute{
							Description: "Date/time the application was created",
							Computed:    true,
						},
						"dev_account": schema.StringAttribute{
							Description: "The developer account which owns this resource's application.",
							Computed:    true,
						},
						"id": schema.StringAttribute{
							Description: "The CipherTrust Manager resource ID of this KMS.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The name given to the KMS.",
						},
						"regions": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "AWS regions managed by the KMS.",
						},
						"status": schema.StringAttribute{
							Computed:    true,
							Description: "The status of the KMS, archived or active.",
						},
						"updated_at": schema.StringAttribute{
							Description: "Date and time the KMS was last updated",
							Computed:    true,
						},
						"uri": schema.StringAttribute{
							Description: "CipherTrust Manager's unique identifier for the resource.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceAWSKms) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_aws_kms.go -> Read]")
	defer tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_aws_kms.go -> Read]")

	var state AWSKmsDataSourceModel
	diags := req.Config.Get(ctx, &state)
	if diags.HasError() {
		resp.Diagnostics = append(resp.Diagnostics, diags...)
		return
	}
	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		val, ok := v.(types.String)
		if ok {
			filters.Add(k, val.ValueString())
		}
	}
	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_AWS+"/kms/", filters)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_aws_kms.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read AWS KMS from CipherTrust Manager",
			err.Error(),
		)
		return
	}
	var kmsList DataSourceKmsListJSON
	err = json.Unmarshal([]byte(jsonStr), &kmsList)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_aws_kms.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read AWS KMS from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	for ndx, kms := range kmsList.Resources {
		kmsTFSDK := KMSModelTFSDK{
			Account:              types.StringValue(kms.Account),
			AccountID:            types.StringValue(kms.AccountID),
			Application:          types.StringValue(kms.Application),
			Arn:                  types.StringValue(kms.Arn),
			AssumeRoleARN:        types.StringValue(kms.AssumeRoleARN),
			AssumeRoleExternalID: types.StringValue(kms.AssumeRoleExternalID),
			AutoAdded:            types.BoolValue(kms.AutoAdded),
			Connection:           types.StringValue(kms.Connection),
			CreatedAt:            types.StringValue(kms.CreatedAt),
			DevAccount:           types.StringValue(kms.DevAccount),
			ID:                   types.StringValue(kms.ID),
			Name:                 types.StringValue(kms.Name),
			Status:               types.StringValue(kms.Status),
			UpdatedAt:            types.StringValue(kms.UpdatedAt),
			URI:                  types.StringValue(kms.URI),
		}
		kmsTFSDK.Regions = utils.StringSliceToListValue(kms.Regions, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		resourceJSON := gjson.Get(jsonStr, "resources").Array()[ndx].String()
		acls.SetAclsStateFromJSON(ctx, gjson.Get(resourceJSON, "acls"), &kmsTFSDK.Acls, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Kmses = append(state.Kmses, kmsTFSDK)
	}
	state.Matched = types.Int64Value(gjson.Get(jsonStr, "total").Int())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
