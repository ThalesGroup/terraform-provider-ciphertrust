package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceCTESignatureSets{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTESignatureSets{}
)

func NewDataSourceCTESignatureSets() datasource.DataSource {
	return &dataSourceCTESignatureSets{}
}

type dataSourceCTESignatureSets struct {
	client *common.Client
}

type CTESignatureSetsDataSourceModel struct {
	SignatureSets []CTESignatureSetsListTFSDK `tfsdk:"signature_sets"`
}

func (d *dataSourceCTESignatureSets) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_signature_sets"
}

func (d *dataSourceCTESignatureSets) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"signature_sets": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"uri": schema.StringAttribute{
							Computed: true,
						},
						"account": schema.StringAttribute{
							Computed: true,
						},
						"created_at": schema.StringAttribute{
							Computed: true,
						},
						"updated_at": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"type": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
						"reference_version": schema.Int64Attribute{
							Computed: true,
						},
						"source_list": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
						"signing_status": schema.StringAttribute{
							Computed: true,
						},
						"percentage_complete": schema.Int64Attribute{
							Computed: true,
						},
						"updated_by": schema.StringAttribute{
							Computed: true,
						},
						"docker_img_id": schema.StringAttribute{
							Computed: true,
						},
						"docker_cont_id": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTESignatureSets) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cte_signature_sets.go -> Read]["+id+"]")
	var state CTESignatureSetsDataSourceModel

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_CTE_SIGNATURE_SET)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_signature_sets.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE signature sets from CM",
			err.Error(),
		)
		return
	}

	signatureSets := []SignatureSetJSON{}

	err = json.Unmarshal([]byte(jsonStr), &signatureSets)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_signature_sets.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE signature sets from CM",
			err.Error(),
		)
		return
	}

	for _, signatureSet := range signatureSets {
		signatureSetState := CTESignatureSetsListTFSDK{}
		signatureSetState.ID = types.StringValue(signatureSet.ID)
		signatureSetState.URI = types.StringValue(signatureSet.URI)
		signatureSetState.Account = types.StringValue(signatureSet.Account)
		signatureSetState.CreatedAt = types.StringValue(signatureSet.CreatedAt)
		signatureSetState.Name = types.StringValue(signatureSet.Name)
		signatureSetState.UpdatedAt = types.StringValue(signatureSet.UpdatedAt)
		signatureSetState.Description = types.StringValue(signatureSet.Description)
		signatureSetState.Type = types.StringValue(signatureSet.Type)
		signatureSetState.ReferenceVersion = types.Int64Value(signatureSet.ReferenceVersion)
		signatureSetState.SigningStatus = types.StringValue(signatureSet.SigningStatus)
		signatureSetState.PercentageComplete = types.Int64Value(signatureSet.PercentageComplete)
		signatureSetState.DockerImgID = types.StringValue(signatureSet.DockerImgID)
		signatureSetState.DockerContID = types.StringValue(signatureSet.DockerContID)

		for _, source := range signatureSet.SourceList {
			signatureSetState.SourceList = append(signatureSetState.SourceList, types.StringValue(source))
		}

		state.SignatureSets = append(state.SignatureSets, signatureSetState)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cte_signature_sets.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTESignatureSets) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
