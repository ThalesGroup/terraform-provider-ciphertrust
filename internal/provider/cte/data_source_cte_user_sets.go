// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

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
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceCTEUserSets{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEUserSets{}
)

func NewDataSourceCTEUserSets() datasource.DataSource {
	return &dataSourceCTEUserSets{}
}

type dataSourceCTEUserSets struct {
	client *common.Client
}

type CTEUserSetsDataSourceModel struct {
	UserSet []CTEUserSetsListTFSDK `tfsdk:"user_sets"`
}

func (d *dataSourceCTEUserSets) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_usersets"
}

func (d *dataSourceCTEUserSets) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"user_sets": schema.ListNestedAttribute{
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
						"labels": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
						"users": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"index": schema.Int64Attribute{
										Optional: true,
									},
									"gid": schema.Int64Attribute{
										Optional: true,
									},
									"gname": schema.StringAttribute{
										Optional: true,
									},
									"os_domain": schema.StringAttribute{
										Optional: true,
									},
									"uid": schema.Int64Attribute{
										Optional: true,
									},
									"uname": schema.StringAttribute{
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

func (d *dataSourceCTEUserSets) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cte_user_sets.go -> Read]["+id+"]")
	var state CTEUserSetsDataSourceModel

	jsonStr, err := d.client.GetAllPaged(ctx, id, common.URL_CTE_USER_SET)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_user_sets.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE usersets from CM",
			err.Error(),
		)
		return
	}

	usersets := []CTEUserSetsListJSON{}

	err = json.Unmarshal([]byte(jsonStr), &usersets)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cte_user_sets.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read CTE usersets from CM",
			err.Error(),
		)
		return
	}

	for _, userset := range usersets {
		userState := CTEUserSetsListTFSDK{}
		userState.ID = types.StringValue(userset.ID)
		userState.URI = types.StringValue(userset.URI)
		userState.Account = types.StringValue(userset.Account)
		userState.CreateAt = types.StringValue(userset.CreatedAt)
		userState.Name = types.StringValue(userset.Name)
		userState.UpdatedAt = types.StringValue(userset.UpdatedAt)
		userState.Description = types.StringValue(userset.Description)

		labelsMap := make(map[string]attr.Value)
		for k, v := range userset.Labels {
			labelsMap[k] = types.StringValue(fmt.Sprintf("%v", v))
		}

		labels, diags := types.MapValue(types.StringType, labelsMap)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		userState.Labels = labels
		for _, userResponse := range userset.Users {
			var uid types.Int64
			if userResponse.UID == nil {
				uid = types.Int64Null()
			} else {
				uid = types.Int64Value(*userResponse.UID)
			}

			var gid types.Int64
			if userResponse.GID == nil {
				gid = types.Int64Null()
			} else {
				gid = types.Int64Value(*userResponse.GID)
			}

			user := CTEUserSetsListItemTFSDK{
				Index:    types.Int64Value(userResponse.Index),
				GID:      gid,
				GName:    types.StringValue(userResponse.GName),
				OSDomain: types.StringValue(userResponse.OSDomain),
				UID:      uid,
				UName:    types.StringValue(userResponse.UName),
			}
			userState.Users = append(userState.Users, user)
		}

		state.UserSet = append(state.UserSet, userState)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cte_user_sets.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEUserSets) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
