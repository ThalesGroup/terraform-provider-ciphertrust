// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

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
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceCTECSIGroup{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTECSIGroup{}
)

func NewDataSourceCTECSIGroup() datasource.DataSource {
	return &dataSourceCTECSIGroup{}
}

type dataSourceCTECSIGroup struct {
	client *common.Client
}

type CTECSIGroupDataSourceModel struct {
	CSIGroups []CTECSIGroupListTFSDK `tfsdk:"csi_group"`
}

func (d *dataSourceCTECSIGroup) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_csi_group"
}

func (d *dataSourceCTECSIGroup) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"csi_group": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
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
						"k8s_namespace": schema.StringAttribute{
							Computed: true,
						},
						"k8s_storage_class": schema.StringAttribute{
							Computed: true,
						},
						"client_profile_id": schema.StringAttribute{
							Computed: true,
						},
						"client_profile_name": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTECSIGroup) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_ctecsigroup.go -> Read]["+id+"]")
	var state CTECSIGroupDataSourceModel
	req.Config.Get(ctx, &state)

	jsonStr, err := d.client.GetAllPaged(ctx, id, common.URL_CTE_CSIGROUP)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_ctecsigroup.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}

	csi_groups := []CTECSIGroupListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &csi_groups)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_ctecsigroup.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}

	for _, csi_group := range csi_groups {
		csi_groups := CTECSIGroupListTFSDK{}
		csi_groups.ID = types.StringValue(csi_group.ID)
		csi_groups.Name = types.StringValue(csi_group.Name)
		csi_groups.Description = types.StringValue(csi_group.Description)
		csi_groups.URI = types.StringValue(csi_group.URI)
		csi_groups.Account = types.StringValue(csi_group.Account)
		csi_groups.CreatedAt = types.StringValue(csi_group.CreatedAt)
		csi_groups.UpdatedAt = types.StringValue(csi_group.UpdatedAt)
		csi_groups.K8sNamespace = types.StringValue(csi_group.K8sNamespace)
		csi_groups.K8sStorageClass = types.StringValue(csi_group.K8sStorageClass)
		csi_groups.ClientProfileID = types.StringValue(csi_group.ClientProfileID)
		csi_groups.ClientProfileName = types.StringValue(csi_group.ClientProfileName)

		state.CSIGroups = append(state.CSIGroups, csi_groups)
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_ctecsigroup.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTECSIGroup) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
