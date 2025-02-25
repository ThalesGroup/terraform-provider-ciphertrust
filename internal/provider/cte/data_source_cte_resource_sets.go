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
	_ datasource.DataSource              = &dataSourceCTEResourceSets{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEResourceSets{}
)

func NewDataSourceCTEResourceSets() datasource.DataSource {
	return &dataSourceCTEResourceSets{}
}

type dataSourceCTEResourceSets struct {
	client *common.Client
}

type CTEResourceSetsDataSourceModel struct {
	ResourceSet []CTEResourceSetsListTFSDK `tfsdk:"resource_sets"`
}

func (d *dataSourceCTEResourceSets) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_resource_sets"
}

func (d *dataSourceCTEResourceSets) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"resource_sets": schema.ListNestedAttribute{
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
						"type": schema.StringAttribute{
							Computed: true,
						},
						"resources": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"index": schema.Int64Attribute{
										Optional: true,
									},
									"directory": schema.StringAttribute{
										Optional: true,
									},
									"file": schema.StringAttribute{
										Optional: true,
									},
									"include_subfolders": schema.BoolAttribute{
										Optional: true,
									},
									"hdfs": schema.BoolAttribute{
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

func (d *dataSourceCTEResourceSets) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cte_resource_sets.go -> Read]["+id+"]")
	var state CTEResourceSetsDataSourceModel

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_CTE_RESOURCE_SET)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_resource_sets.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE resource sets from CM",
			err.Error(),
		)
		return
	}

	resourceSets := []CTEResourceSetsListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &resourceSets)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_resource_sets.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE resource sets from CM",
			err.Error(),
		)
		return
	}

	for _, resourceSet := range resourceSets {
		resourceSetState := CTEResourceSetsListTFSDK{}
		resourceSetState.ID = types.StringValue(resourceSet.ID)
		resourceSetState.URI = types.StringValue(resourceSet.URI)
		resourceSetState.Account = types.StringValue(resourceSet.Account)
		resourceSetState.CreateAt = types.StringValue(resourceSet.CreatedAt)
		resourceSetState.Name = types.StringValue(resourceSet.Name)
		resourceSetState.UpdatedAt = types.StringValue(resourceSet.UpdatedAt)
		resourceSetState.Description = types.StringValue(resourceSet.Description)
		resourceSetState.Type = types.StringValue(resourceSet.Type)

		for _, resource := range resourceSet.Resources {
			_resourceData := CTEResourceSetListItemTFSDK{
				Index:             types.Int64Value(resource.Index),
				Directory:         types.StringValue(resource.Directory),
				File:              types.StringValue(resource.File),
				IncludeSubfolders: types.BoolValue(resource.IncludeSubfolders),
				HDFS:              types.BoolValue(resource.HDFS),
			}
			resourceSetState.Resources = append(resourceSetState.Resources, _resourceData)
		}

		state.ResourceSet = append(state.ResourceSet, resourceSetState)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cte_resource_sets.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEResourceSets) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
