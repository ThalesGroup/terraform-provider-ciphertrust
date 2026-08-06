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
	Limit       types.Int64                `tfsdk:"limit"`
	Skip        types.Int64                `tfsdk:"skip"`
	ResourceSet []CTEResourceSetsListTFSDK `tfsdk:"resource_sets"`
}

func (d *dataSourceCTEResourceSets) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_resource_sets"
}

func (d *dataSourceCTEResourceSets) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of resource sets to return. If unset, all resource sets are returned (a warning is emitted if the result set is large).",
			},
			"skip": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of resource sets to skip before returning results, for pagination. Defaults to 0.",
			},
			"resource_sets": schema.ListNestedAttribute{
				Description: "List of resource sets.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The unique identifier of the resource set.",
							Computed:    true,
						},
						"uri": schema.StringAttribute{
							Description: "URI of the resource set.",
							Computed:    true,
						},
						"account": schema.StringAttribute{
							Description: "Account of the resource set.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "Date and time the resource set was created.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of the resource set.",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "Date and time the resource set was last updated.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "Description of the resource set.",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "Type of the resource set, Directory or Classification.",
							Computed:    true,
						},
						"labels": schema.MapAttribute{
							Description: "Labels applied to the resource set.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"resources": schema.ListNestedAttribute{
							Description: "List of resources (directories/files) belonging to the resource set.",
							Optional:    true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"index": schema.Int64Attribute{
										Description: "Index of the resource within the resource set.",
										Optional:    true,
									},
									"directory": schema.StringAttribute{
										Description: "Directory of the resource.",
										Optional:    true,
									},
									"file": schema.StringAttribute{
										Description: "File name or pattern of the resource.",
										Optional:    true,
									},
									"include_subfolders": schema.BoolAttribute{
										Description: "Whether to include subfolders of the directory in the resource.",
										Optional:    true,
									},
									"hdfs": schema.BoolAttribute{
										Description: "Whether this resource is HDFS (Hadoop Distributed File System).",
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

func (d *dataSourceCTEResourceSets) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_cte_resource_sets.go -> Read][" + id + "]")
	var state CTEResourceSetsDataSourceModel
	req.Config.Get(ctx, &state)

	limitVal, skipVal := resolvePagedListParams(state.Limit, state.Skip)
	jsonStr, total, err := d.client.GetAllPagedWithLimit(ctx, id, common.URL_CTE_RESOURCE_SET, skipVal, limitVal)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_resource_sets.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE resource sets from CM",
			err.Error(),
		)
		return
	}
	warnIfPagedResultLarge(&resp.Diagnostics, "CTE resource sets", total, limitVal)

	resourceSets := []CTEResourceSetsListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &resourceSets)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_resource_sets.go -> Read][" + id + "]")
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

		labelsMap := make(map[string]attr.Value)
		for k, v := range resourceSet.Labels {
			labelsMap[k] = types.StringValue(fmt.Sprintf("%v", v))
		}

		labels, diags := types.MapValue(types.StringType, labelsMap)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		resourceSetState.Labels = labels

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

	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_cte_resource_sets.go -> Read][" + id + "]")
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
