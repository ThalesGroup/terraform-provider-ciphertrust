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
	_ datasource.DataSource              = &dataSourceCTEProcessSets{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEProcessSets{}
)

func NewDataSourceCTEProcessSets() datasource.DataSource {
	return &dataSourceCTEProcessSets{}
}

type dataSourceCTEProcessSets struct {
	client *common.Client
}

type CTEProcessSetsDataSourceModel struct {
	ProcessSets []CTEProcessSetsListTFSDK `tfsdk:"process_sets"`
}

func (d *dataSourceCTEProcessSets) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_process_sets"
}

func (d *dataSourceCTEProcessSets) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"process_sets": schema.ListNestedAttribute{
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
						"name": schema.StringAttribute{
							Computed: true,
						},
						"updated_at": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
						"processes": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"index": schema.Int64Attribute{
										Optional: true,
									},
									"directory": schema.StringAttribute{
										Optional: true,
									},
									"signature": schema.StringAttribute{
										Optional: true,
									},
									"file": schema.StringAttribute{
										Optional: true,
									},
									"resource_set_id": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEProcessSets) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cte_process_sets.go -> Read]["+id+"]")
	var state CTEProcessSetsDataSourceModel

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_CTE_PROCESS_SET)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_process_sets.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE process sets from CM",
			err.Error(),
		)
		return
	}

	processSets := []CTEProcessSetListItemJSON{}

	err = json.Unmarshal([]byte(jsonStr), &processSets)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_process_sets.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE process sets from CM",
			err.Error(),
		)
		return
	}

	for _, processSet := range processSets {
		processSetState := CTEProcessSetsListTFSDK{}
		processSetState.ID = types.StringValue(processSet.ID)
		processSetState.URI = types.StringValue(processSet.URI)
		processSetState.Account = types.StringValue(processSet.Account)
		processSetState.CreateAt = types.StringValue(processSet.CreatedAt)
		processSetState.Name = types.StringValue(processSet.Name)
		processSetState.UpdatedAt = types.StringValue(processSet.UpdatedAt)
		processSetState.Description = types.StringValue(processSet.Description)

		for _, process := range processSet.Processes {
			_processData := CTEProcessSetListItemTFSDK{
				Index:         types.Int64Value(process.Index),
				Directory:     types.StringValue(process.Directory),
				File:          types.StringValue(process.File),
				Signature:     types.StringValue(process.Signature),
				ResourceSetID: types.StringValue(process.ResourceSetID),
			}
			processSetState.Processes = append(processSetState.Processes, _processData)
		}

		state.ProcessSets = append(state.ProcessSets, processSetState)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cte_process_sets.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEProcessSets) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
