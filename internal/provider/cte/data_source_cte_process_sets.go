package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
	Limit       types.Int64               `tfsdk:"limit"`
	Skip        types.Int64               `tfsdk:"skip"`
	ProcessSets []CTEProcessSetsListTFSDK `tfsdk:"process_sets"`
}

func (d *dataSourceCTEProcessSets) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_process_sets"
}

func (d *dataSourceCTEProcessSets) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of process sets to return. If unset, all process sets are returned (a warning is emitted if the result set is large).",
			},
			"skip": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of process sets to skip before returning results, for pagination. Defaults to 0.",
			},
			"process_sets": schema.ListNestedAttribute{
				Description: "List of process sets.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The unique identifier of the process set.",
							Computed:    true,
						},
						"uri": schema.StringAttribute{
							Description: "URI of the process set.",
							Computed:    true,
						},
						"account": schema.StringAttribute{
							Description: "Account of the process set.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "Date and time the process set was created.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of the process set.",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "Date and time the process set was last updated.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "Description of the process set.",
							Computed:    true,
						},
						"labels": schema.MapAttribute{
							Description: "Labels applied to the process set.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"processes": schema.ListNestedAttribute{
							Description: "List of processes belonging to the process set.",
							Optional:    true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"index": schema.Int64Attribute{
										Description: "Index of the process within the process set.",
										Optional:    true,
									},
									"directory": schema.StringAttribute{
										Description: "Directory containing the process executable.",
										Optional:    true,
									},
									"signature": schema.StringAttribute{
										Description: "Signature associated with the process, used to identify the process.",
										Optional:    true,
									},
									"file": schema.StringAttribute{
										Description: "Name of the process executable file.",
										Optional:    true,
									},
									"resource_set_id": schema.StringAttribute{
										Description: "ID of the resource set linked to the process.",
										Optional:    true,
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
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_cte_process_sets.go -> Read][" + id + "]")
	var state CTEProcessSetsDataSourceModel
	req.Config.Get(ctx, &state)

	limitVal, skipVal := resolvePagedListParams(state.Limit, state.Skip)
	jsonStr, total, err := d.client.GetAllPagedWithLimit(ctx, id, common.URL_CTE_PROCESS_SET, skipVal, limitVal)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_process_sets.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE process sets from CM",
			err.Error(),
		)
		return
	}
	warnIfPagedResultLarge(&resp.Diagnostics, "CTE process sets", total, limitVal)

	processSets := []CTEProcessSetListItemJSON{}

	err = json.Unmarshal([]byte(jsonStr), &processSets)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_process_sets.go -> Read][" + id + "]")
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

		labelsMap := make(map[string]attr.Value)
		for k, v := range processSet.Labels {
			labelsMap[k] = types.StringValue(fmt.Sprintf("%v", v))
		}

		labels, diags := types.MapValue(types.StringType, labelsMap)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		processSetState.Labels = labels

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

	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_cte_process_sets.go -> Read][" + id + "]")
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
