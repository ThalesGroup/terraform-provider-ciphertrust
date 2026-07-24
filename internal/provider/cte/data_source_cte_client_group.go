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
	_ datasource.DataSource              = &dataSourceCTEClientGroup{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEClientGroup{}
)

func NewDataSourceCTEClientGroup() datasource.DataSource {
	return &dataSourceCTEClientGroup{}
}

type dataSourceCTEClientGroup struct {
	client *common.Client
}

type CTEClientGroupDataSourceModel struct {
	ClientGroups []CTEClientGroupListTFSDK `tfsdk:"client_groups"`
}

func (d *dataSourceCTEClientGroup) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_client_group"
}

func (d *dataSourceCTEClientGroup) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"client_groups": schema.ListNestedAttribute{
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
						"application": schema.StringAttribute{
							Computed: true,
						},
						"dev_account": schema.StringAttribute{
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
						"description": schema.StringAttribute{
							Computed: true,
						},
						"domain_list": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
						"account_list": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
						"enable_domain_sharing": schema.BoolAttribute{
							Computed: true,
						},
						"native_domain": schema.StringAttribute{
							Computed: true,
						},
						"cluster_type": schema.StringAttribute{
							Computed: true,
						},
						"client_locked": schema.BoolAttribute{
							Computed: true,
						},
						"system_locked": schema.BoolAttribute{
							Computed: true,
						},
						"password_creation_method": schema.StringAttribute{
							Computed: true,
						},
						"communication_enabled": schema.BoolAttribute{
							Computed: true,
						},
						"auth_binaries": schema.StringAttribute{
							Computed: true,
						},
						"capabilities": schema.StringAttribute{
							Computed: true,
						},
						"enabled_capabilities": schema.StringAttribute{
							Computed: true,
						},
						"profile_id": schema.StringAttribute{
							Computed: true,
						},
						"profile_name": schema.StringAttribute{
							Computed: true,
						},
						"ldt_status": schema.StringAttribute{
							Computed: true,
						},
						"enable_ldt_passive": schema.BoolAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEClientGroup) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cteclientgroup.go -> Read]["+id+"]")
	var state CTEClientGroupDataSourceModel
	req.Config.Get(ctx, &state)

	jsonStr, err := d.client.GetAllPaged(ctx, id, common.URL_CTE_CLIENT_GROUP)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cteclientgroup.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}

	client_groups := []CTEClientGroupListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &client_groups)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cteclientgroup.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}

	for _, group := range client_groups {
		client_group := CTEClientGroupListTFSDK{}
		client_group.ID = types.StringValue(group.ID)
		client_group.URI = types.StringValue(group.URI)
		client_group.Account = types.StringValue(group.Account)
		client_group.Application = types.StringValue(group.Application)
		client_group.DevAccount = types.StringValue(group.DevAccount)
		client_group.CreatedAt = types.StringValue(group.CreatedAt)
		client_group.UpdatedAt = types.StringValue(group.UpdatedAt)
		client_group.Name = types.StringValue(group.Name)
		client_group.Description = types.StringValue(group.Description)
		client_group.EnableDomainSharing = types.BoolValue(group.EnableDomainSharing)
		client_group.NativeDomain = types.StringValue(group.NativeDomain)
		client_group.ClusterType = types.StringValue(group.ClusterType)
		client_group.ClientLocked = types.BoolValue(group.ClientLocked)
		client_group.SystemLocked = types.BoolValue(group.SystemLocked)
		client_group.PasswordCreationMethod = types.StringValue(group.PasswordCreationMethod)
		client_group.CommunicationEnabled = types.BoolValue(group.CommunicationEnabled)
		client_group.AuthBinaries = types.StringValue(group.AuthBinaries)
		client_group.Capabilities = types.StringValue(group.Capabilities)
		client_group.EnabledCapabilities = types.StringValue(group.EnabledCapabilities)
		client_group.ProfileID = types.StringValue(group.ProfileID)
		client_group.ProfileName = types.StringValue(group.ProfileName)
		client_group.LDTStatus = types.StringValue(group.LDTStatus)
		client_group.EnableLDTPassive = types.BoolValue(group.EnableLDTPassive)

		var accountSlice []string

		if group.AccountList != "" {
			err := json.Unmarshal([]byte(group.AccountList), &accountSlice)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error parsing account_list",
					err.Error(),
				)
				return
			}
		}

		accountListTF, diags := types.ListValueFrom(ctx, types.StringType, accountSlice)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		client_group.AccountList = accountListTF

		var domainSlice []string

		if group.DomainList != "" {
			err := json.Unmarshal([]byte(group.DomainList), &domainSlice)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error parsing domain_list",
					err.Error(),
				)
				return
			}
		}

		domainListTF, diags := types.ListValueFrom(ctx, types.StringType, domainSlice)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		client_group.DomainList = domainListTF

		state.ClientGroups = append(state.ClientGroups, client_group)
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cteclientgroup.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEClientGroup) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
