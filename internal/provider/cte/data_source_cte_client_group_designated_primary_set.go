package cte

import (
	"context"
	"encoding/json"
	"fmt"
	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"strings"
)

var (
	_ datasource.DataSource              = &dataSourceCTEClientGroupDesignatedPrimarySet{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEClientGroupDesignatedPrimarySet{}
)

func NewDataSourceCTEClientGroupDesignatedPrimarySet() datasource.DataSource {
	return &dataSourceCTEClientGroupDesignatedPrimarySet{}
}

type dataSourceCTEClientGroupDesignatedPrimarySet struct {
	client *common.Client
}

type CTEClientGroupDesignatedPrimarySetDataSourceModel struct {
	ClientGroupName  types.String                                  `tfsdk:"client_group_name"`
	Limit            types.Int64                                   `tfsdk:"limit"`
	Skip             types.Int64                                   `tfsdk:"skip"`
	ClientGroupDpSet []CTEClientGroupDesignatedPrimarySetListTFSDK `tfsdk:"client_group_dp_set"`
}

func (d *dataSourceCTEClientGroupDesignatedPrimarySet) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_client_group_dp_set"
}

func (d *dataSourceCTEClientGroupDesignatedPrimarySet) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"client_group_name": schema.StringAttribute{
				Description: "Name of the client group",
				Required:    true,
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of designated primary set entries to return. If unset, all entries are returned (a warning is emitted if the result set is large).",
			},
			"skip": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of designated primary set entries to skip before returning results, for pagination. Defaults to 0.",
			},
			"client_group_dp_set": schema.ListNestedAttribute{
				Description: "List of client group dp sets",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "ID of the client group dp set",
							Computed:    true,
						},
						"uri": schema.StringAttribute{
							Description: "URI of the client group dp set",
							Computed:    true,
						},
						"account": schema.StringAttribute{
							Description: "Account of the client group dp set",
							Computed:    true,
						},
						"application": schema.StringAttribute{
							Description: "Application of the client group dp set",
							Computed:    true,
						},
						"dev_account": schema.StringAttribute{
							Description: "Dev account of the client group dp set",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "Created at of the client group dp set",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "Updated at of the client group dp set",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of the client group dp set",
							Computed:    true,
						},
						"client_group_id": schema.StringAttribute{
							Description: "Client group ID of the client group dp set",
							Computed:    true,
						},
						"ldt_comm_group_service_id": schema.StringAttribute{
							Description: "LDT comm group Id",
							Computed:    true,
						},
						"primary_client_id_list": schema.ListAttribute{
							Description: "List of primary client IDs",
							Computed:    true,
							ElementType: types.StringType,
						},
						"primary_client_name_list": schema.ListAttribute{
							Description: "List of primary client names",
							Computed:    true,
							ElementType: types.StringType,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEClientGroupDesignatedPrimarySet) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_cte_clientgroupdpset.go -> Read][" + id + "]")
	var state CTEClientGroupDesignatedPrimarySetDataSourceModel
	req.Config.Get(ctx, &state)
	limitVal, skipVal := resolvePagedListParams(state.Limit, state.Skip)
	jsonStr, total, err := d.client.GetAllPagedWithLimit(ctx, id, common.URL_CTE_CLIENT_GROUP+"/"+state.ClientGroupName.ValueString()+"/dps", skipVal, limitVal)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_clientgroupdpset.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}
	warnIfPagedResultLarge(&resp.Diagnostics, "CTE client group designated primary set entries", total, limitVal)
	client_group_dps := []CTEClientGroupDesignatedPrimarySetListJSON{}
	err = json.Unmarshal([]byte(jsonStr), &client_group_dps)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cte_clientgroupdpset.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}

	for _, client_group_dp := range client_group_dps {
		client_group_dp_set := CTEClientGroupDesignatedPrimarySetListTFSDK{}
		client_group_dp_set.ID = types.StringValue(client_group_dp.ID)
		client_group_dp_set.URI = types.StringValue(client_group_dp.URI)
		client_group_dp_set.Account = types.StringValue(client_group_dp.Account)
		client_group_dp_set.Application = types.StringValue(client_group_dp.Application)
		client_group_dp_set.DevAccount = types.StringValue(client_group_dp.DevAccount)
		client_group_dp_set.CreatedAt = types.StringValue(client_group_dp.CreatedAt)
		client_group_dp_set.UpdatedAt = types.StringValue(client_group_dp.UpdatedAt)
		client_group_dp_set.Name = types.StringValue(client_group_dp.Name)
		client_group_dp_set.ClientGroupID = types.StringValue(client_group_dp.ClientGroupID)
		client_group_dp_set.LdtCommGroupServiceID = types.StringValue(client_group_dp.LdtCommGroupServiceID)
		client_group_dp_set.PrimaryClientIDList = []types.String{}
		client_group_dp_set.PrimaryClientNameList = []types.String{}
		if client_group_dp.PrimaryClientIDList != "" {
			ids := strings.Split(client_group_dp.PrimaryClientIDList, ",")
			for _, id := range ids {
				client_group_dp_set.PrimaryClientIDList = append(client_group_dp_set.PrimaryClientIDList, types.StringValue(id))
			}
		}
		if client_group_dp.PrimaryClientNameList != "" {
			names := strings.Split(client_group_dp.PrimaryClientNameList, ",")
			for _, name := range names {
				client_group_dp_set.PrimaryClientNameList = append(client_group_dp_set.PrimaryClientNameList, types.StringValue(name))
			}
		}
		state.ClientGroupDpSet = append(state.ClientGroupDpSet, client_group_dp_set)
	}
	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_cte_clientgroupdpset.go -> Read][" + id + "]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEClientGroupDesignatedPrimarySet) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
