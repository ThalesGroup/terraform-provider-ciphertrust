package cm

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
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceCMGroup{}
	_ datasource.DataSourceWithConfigure = &dataSourceCMGroup{}
)

func NewDataSourceCMGroup() datasource.DataSource {
	return &dataSourceCMGroup{}
}

type dataSourceCMGroup struct {
	client *common.Client
}

func (d *dataSourceCMGroup) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_group"
}

func (d *dataSourceCMGroup) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the group to read.",
			},
			"description": schema.StringAttribute{
				Computed: true,
			},
			"app_metadata": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
			"client_metadata": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
			"user_metadata": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
			"id": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (d *dataSourceCMGroup) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cm_group.go -> Read]["+id+"]")

	var state CMGroupTFSDK
	diags := req.Config.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupResponse, err := d.client.GetById(ctx, id, state.Name.ValueString(), common.URL_GROUP)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_group.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read group from CM",
			err.Error(),
		)
		return
	}

	var group CMGroupJSON
	if err := json.Unmarshal([]byte(groupResponse), &group); err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_group.go -> Read]["+id+"]")
		resp.Diagnostics.AddError("Unable to read group from CM", err.Error())
		return
	}

	state.Name = types.StringValue(group.Name)
	state.Description = types.StringValue(group.Description)
	state.ID = types.StringValue(group.Name)
	state.AppMetadata = cmGroupMetadataToTF(group.AppMetadata)
	state.ClientMetadata = cmGroupMetadataToTF(group.ClientMetadata)
	state.UserMetadata = cmGroupMetadataToTF(group.UserMetadata)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cm_group.go -> Read]["+id+"]")
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (d *dataSourceCMGroup) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func cmGroupMetadataToTF(m map[string]interface{}) types.Map {
	if len(m) == 0 {
		return types.MapNull(types.StringType)
	}
	elems := make(map[string]attr.Value, len(m))
	for k, v := range m {
		elems[k] = types.StringValue(fmt.Sprintf("%v", v))
	}
	mv, _ := types.MapValue(types.StringType, elems)
	return mv
}
