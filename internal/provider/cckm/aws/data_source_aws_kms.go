package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"net/url"

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

func NewDataSourceAWSKms() datasource.DataSource {
	return &dataSourceAWSKms{}
}

func (d *dataSourceAWSKms) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *dataSourceAWSKms) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_kms"
}

func (d *dataSourceAWSKms) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of AWS KMS resources.",
		Attributes: map[string]schema.Attribute{
			"aws_connection": schema.StringAttribute{
				Optional:    true,
				Description: "Name or ID of the AWS connection. If provided, details of all KMS resources belonging to this connection will be retrieved.",
			},
			"kms_id": schema.StringAttribute{
				Optional:    true,
				Description: "Terraform or CipherTrust AWS KMS resource ID.",
			},
			"kms_name": schema.StringAttribute{
				Optional:    true,
				Description: "Name of an AWS KMS. If provided, only details for this KMS will be retrieved.",
			},
			"kms": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"aws_connection": schema.StringAttribute{
							Computed:    true,
							Description: "Name or ID of the AWS connection.",
						},
						"kms_id": schema.StringAttribute{
							Computed:    true,
							Description: "Terraform or CipherTrust AWS KMS resource ID.",
						},
						"kms_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the AWS KMS.",
						},
						"regions": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "AWS regions assigned to the AWS KMS.",
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
	if state.AwsConnection.ValueString() != "" {
		payload := AccountDetailsInputModelJSON{
			AwsConnection: state.AwsConnection.ValueString(),
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
		accountID := gjson.Get(response, "account_id").String()
		filters.Add("account_id", accountID)
	} else {
		if state.KmsID.ValueString() != "" {
			filters.Add("id", state.KmsID.ValueString())
		}
		if state.KmsName.ValueString() != "" {
			filters.Add("name", state.KmsName.ValueString())
		}
	}
	response := d.listAwsKms(ctx, id, filters, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resources := gjson.Get(response, "resources").Array()
	for _, resource := range resources {
		kmsState := AWSKmsDataSourceTFSDK{}
		kmsState.KmsID = types.StringValue(gjson.Get(resource.String(), "id").String())
		kmsState.AwsConnection = types.StringValue(gjson.Get(resource.String(), "connect").String())
		kmsState.KmsName = types.StringValue(gjson.Get(resource.String(), "name").String())
		regionJSON := gjson.Get(resource.String(), "regions").Array()
		var regions []attr.Value
		for _, region := range regionJSON {
			regions = append(regions, types.StringValue(region.String()))
		}
		regionsList, dg := types.ListValue(types.StringType, regions)
		if dg.HasError() {
			resp.Diagnostics = append(resp.Diagnostics, dg...)
		}
		kmsState.Regions = regionsList
		state.KmsList = append(state.KmsList, kmsState)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (d *dataSourceAWSKms) listAwsKms(ctx context.Context, id string, filters url.Values, diags *diag.Diagnostics) string {
	response, err := d.client.ListWithFilters(ctx, id, common.URL_AWS_KMS, filters)
	if err != nil {
		msg := "Error listing AWS KMS."
		details := apiError(msg, map[string]interface{}{"error": err.Error(), "filters": fmt.Sprintf("%v", filters)})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	if diags.HasError() {
		return ""
	}
	return response
}
