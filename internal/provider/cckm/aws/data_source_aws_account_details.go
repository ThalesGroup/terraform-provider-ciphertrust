package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceAWSAccountDetails{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSAccountDetails{}
)

func NewDataSourceAWSAccountDetails() datasource.DataSource {
	return &dataSourceAWSAccountDetails{}
}

func (d *dataSourceAWSAccountDetails) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

const (
	AccountsURL = "api/v1/cckm/aws/accounts"
)

type dataSourceAWSAccountDetails struct {
	client *common.Client
}

type AWSAccountDetailsDataSourceModel struct {
	AWSAccountDetailsModelTFSDK
}

func (d *dataSourceAWSAccountDetails) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_account_details"
}

func (d *dataSourceAWSAccountDetails) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve the account and regions associated with the AWS connection.",
		Attributes: map[string]schema.Attribute{
			"aws_connection": schema.StringAttribute{
				Required:    true,
				Description: "Name or ID of the AWS connection.",
			},
			"account_id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS account ID managed by the connection.",
			},
			"regions": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "AWS regions available for the account.",
			},
			"validate": schema.BoolAttribute{
				Optional:    true,
				Description: "Validate that the AWS account is already managed by a connection.",
			},
			"assume_role_arn": schema.StringAttribute{
				Optional:    true,
				Description: "Amazon Resource Name (ARN) of the role to be assumed.",
			},
			"assume_role_external_id": schema.StringAttribute{
				Optional:    true,
				Description: "External ID for the role to be assumed. This parameter can be specified only with 'assume_role_arn'.",
			},
		},
	}
}

func (d *dataSourceAWSAccountDetails) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_aws_account_details.go -> Read]")
	defer tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_aws_account_details.go -> Read]")
	var state AWSAccountDetailsDataSourceModel
	diags := req.Config.Get(ctx, &state)
	if diags.HasError() {
		resp.Diagnostics = append(resp.Diagnostics, diags...)
		return
	}
	id := state.Connection.ValueString()
	var payload AccountDetailsInputModelJSON
	payload.AWSConnection = state.Connection.ValueString()
	if !state.AssumeRoleExternalID.IsNull() {
		payload.AssumeRoleArn = state.AssumeRoleArn.ValueString()
	}
	if !state.AssumeRoleArn.IsNull() {
		payload.AssumeRoleExternalID = state.AssumeRoleArn.ValueString()
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error reading AWS account details, invalid data input."
		details := apiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err := d.client.PostDataV2(ctx, id, AccountsURL, payloadJSON)
	if err != nil {
		msg := "Error reading AWS account details."
		details := apiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	state.AccountID = types.StringValue(gjson.Get(response, "account_id").String())
	state.Regions = stringSliceJSONToListValue(gjson.Get(response, "regions").Array(), &resp.Diagnostics)
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}
