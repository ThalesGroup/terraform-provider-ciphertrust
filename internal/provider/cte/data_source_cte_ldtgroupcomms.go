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
)

var (
	_ datasource.DataSource              = &dataSourceLDTGroupCommSvc{}
	_ datasource.DataSourceWithConfigure = &dataSourceLDTGroupCommSvc{}
)

func NewDataSourceLDTGroupCommSvc() datasource.DataSource {
	return &dataSourceLDTGroupCommSvc{}
}

type dataSourceLDTGroupCommSvc struct {
	client *common.Client
}

type CTELDTGroupCommSvcDataSourceModel struct {
	GroupName     types.String               `tfsdk:"group_name"`
	LDTCommGroups []LDTGroupCommSvcListTFSDK `tfsdk:"ldt_comm_groups"`
}

func (d *dataSourceLDTGroupCommSvc) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ldt_comm_group_svc_list"
}

func (d *dataSourceLDTGroupCommSvc) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"group_name": schema.StringAttribute{
				Description: "Name of the LDT communication group to filter by. If omitted, all LDT communication groups are returned.",
				Optional:    true,
			},
			"ldt_comm_groups": schema.ListNestedAttribute{
				Description: "List of LDT (Live Data Transformation) communication groups matching the given filter.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The unique identifier of the LDT communication group.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of the LDT communication group.",
							Computed:    true,
						},
						"uri": schema.StringAttribute{
							Description: "URI of the LDT communication group.",
							Computed:    true,
						},
						"account": schema.StringAttribute{
							Description: "Account of the LDT communication group.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "Date and time the LDT communication group was created.",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "Date and time the LDT communication group was last updated.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "Description of the LDT communication group.",
							Computed:    true,
						},
						"dev_account": schema.StringAttribute{
							Description: "Dev account of the LDT communication group.",
							Computed:    true,
						},
						"health_status": schema.StringAttribute{
							Description: "Health status of the LDT communication group.",
							Computed:    true,
						},
						"application": schema.StringAttribute{
							Description: "Application associated with the LDT communication group.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceLDTGroupCommSvc) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_ldtgruoupcomms.go -> Read][" + id + "]")
	var state CTELDTGroupCommSvcDataSourceModel
	req.Config.Get(ctx, &state)
	d.client.Log.Info("PrathamMaini =====> " + state.GroupName.ValueString())

	jsonStr, err := d.client.GetAllPaged(ctx, id, common.URL_LDT_GROUP_COMM_SVC+"?name="+state.GroupName.ValueString())
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_ldtgruoupcomms.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}

	ldt_comm_groups := []LDTGroupCommSvcListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &ldt_comm_groups)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_ldtgruoupcomms.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}

	for _, group := range ldt_comm_groups {
		comm_group := LDTGroupCommSvcListTFSDK{}
		comm_group.ID = types.StringValue(group.ID)
		comm_group.Name = types.StringValue(group.Name)
		comm_group.URI = types.StringValue(group.URI)
		comm_group.Account = types.StringValue(group.Account)
		comm_group.CreatedAt = types.StringValue(group.CreatedAt)
		comm_group.UpdatedAt = types.StringValue(group.UpdatedAt)
		comm_group.Description = types.StringValue(group.Description)
		comm_group.DevAccount = types.StringValue(group.DevAccount)
		comm_group.HealthStatus = types.StringValue(group.HealthStatus)
		comm_group.Application = types.StringValue(group.Application)
		state.LDTCommGroups = append(state.LDTCommGroups, comm_group)
	}

	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_ldtgruoupcomms.go -> Read][" + id + "]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceLDTGroupCommSvc) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
