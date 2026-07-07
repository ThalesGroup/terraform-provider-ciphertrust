// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &resourceCTEUserSet{}
	_ resource.ResourceWithConfigure   = &resourceCTEUserSet{}
	_ resource.ResourceWithImportState = &resourceCTEUserSet{}
)

func NewResourceCTEUserSet() resource.Resource {
	return &resourceCTEUserSet{}
}

type resourceCTEUserSet struct {
	client *common.Client
}

func (r *resourceCTEUserSet) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_user_set"
}

// Schema defines the schema for the resource.
func (r *resourceCTEUserSet) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the resource",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"uri": schema.StringAttribute{
				Description: "A human readable unique identifier of the resource",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"account": schema.StringAttribute{
				Description: "The account which owns this resource.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dev_account": schema.StringAttribute{
				Description: "The developer account which owns this resource's application.",
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"application": schema.StringAttribute{
				Description: "The application this resource belongs to.",
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"name": schema.StringAttribute{
				Description: "Name of the user set.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the user set.",
				Optional:    true,
			},
			"labels": schema.MapAttribute{
				Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/. To add a label, set the label's value as follows.\n\"labels\": {\n\t\"key1\": \"value1\",\n\t\"key2\": \"value2\"\n}",
				ElementType: types.StringType,
				Optional:    true,
				Default: mapdefault.StaticValue(
					types.MapValueMust(types.StringType, map[string]attr.Value{}),
				),
				Computed: true,
			},
			"users": schema.ListNestedAttribute{
				Description: "List of users to be added to the user set.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"gid": schema.Int64Attribute{
							Description: "Group ID of the user to be added to the user set.",
							Optional:    true,
						},
						"gname": schema.StringAttribute{
							Description: "Group name of the user to be added to the user set.",
							Optional:    true,
						},
						"os_domain": schema.StringAttribute{
							Description: "OS domain name for Windows platforms.",
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(""),
						},
						"uid": schema.Int64Attribute{
							Description: "ID of the user to be added to the user set.",
							Optional:    true,
						},
						"uname": schema.StringAttribute{
							Description: "Name of the user to be added to the user set.",
							Optional:    true,
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEUserSet) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_user_set.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTEUserSetTFSDK
	payload := map[string]interface{}{}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload["name"] = common.TrimString(plan.Name.String())
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload["description"] = common.TrimString(plan.Description.String())
	}
	var usersJSONArr []CTEUserJSON
	for _, user := range plan.Users {
		var userJSON CTEUserJSON

		if !user.GID.IsNull() {
			gid := int(user.GID.ValueInt64())
			userJSON.GID = &gid
		}

		if !user.UID.IsNull() {
			uid := int(user.UID.ValueInt64())
			userJSON.UID = &uid
		}

		if user.OSDomain.ValueString() != "" && user.OSDomain.ValueString() != types.StringNull().ValueString() {
			userJSON.OSDomain = string(user.OSDomain.ValueString())
		}
		if user.UName.ValueString() != "" && user.UName.ValueString() != types.StringNull().ValueString() {
			userJSON.UName = string(user.UName.ValueString())
		}
		if user.GName.ValueString() != "" && user.GName.ValueString() != types.StringNull().ValueString() {
			userJSON.GName = string(user.GName.ValueString())
		}

		usersJSONArr = append(usersJSONArr, userJSON)
	}
	payload["users"] = usersJSONArr

	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload["labels"] = labelsPayload

	payloadJSON, _ := json.Marshal(payload)

	response, err := r.client.PostDataV2(ctx, id, common.URL_CTE_USER_SET, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE User Set on CipherTrust Manager: ",
			"Could not create CTE User Set, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user_set.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEUserSet) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEUserSetTFSDK
	id := uuid.New().String()

	tflog.Trace(
		ctx,
		common.MSG_METHOD_START+
			"[resource_cte_user_set.go -> Read]["+id+"]",
	)

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_CTE_USER_SET)

	if response == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	var apiResp CTEUserSetJSON

	err = json.Unmarshal([]byte(response), &apiResp)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing API response",
			err.Error(),
		)
		return
	}

	setCTEUserSetState(&state, &apiResp, resp)

	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(
		ctx,
		common.MSG_METHOD_END+
			"[resource_cte_user_set.go -> Read]["+id+"]",
	)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user_set.go -> Read]["+id+"]")
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEUserSet) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEUserSetTFSDK
	payload := map[string]interface{}{}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	//immutable field handling
	if plan.Name.ValueString() != state.Name.ValueString() {
		resp.Diagnostics.AddError("Cannot change user set name once it is created", "Name is an immutable field")
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload["description"] = common.TrimString(plan.Description.String())
	}
	var usersJSONArr []CTEUserJSON
	for _, user := range plan.Users {
		var userJSON CTEUserJSON

		if !user.GID.IsNull() {
			gid := int(user.GID.ValueInt64())
			userJSON.GID = &gid
		}

		if !user.UID.IsNull() {
			uid := int(user.UID.ValueInt64())
			userJSON.UID = &uid
		}

		if user.OSDomain.ValueString() != "" && user.OSDomain.ValueString() != types.StringNull().ValueString() {
			userJSON.OSDomain = string(user.OSDomain.ValueString())
		}
		if user.UName.ValueString() != "" && user.UName.ValueString() != types.StringNull().ValueString() {
			userJSON.UName = string(user.UName.ValueString())
		}
		if user.GName.ValueString() != "" && user.GName.ValueString() != types.StringNull().ValueString() {
			userJSON.GName = string(user.GName.ValueString())
		}

		usersJSONArr = append(usersJSONArr, userJSON)
	}
	payload["users"] = usersJSONArr

	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload["labels"] = labelsPayload

	payloadJSON, _ := json.Marshal(payload)

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_CTE_USER_SET, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE User Set on CipherTrust Manager: ",
			"Could not create CTE User Set, unexpected error: "+err.Error(),
		)
		return
	}

	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEUserSet) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEUserSetTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_USER_SET, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user_set.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE User Set",
			"Could not delete CTE User Set, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEUserSet) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

func setCTEUserSetState(
	state *CTEUserSetTFSDK,
	apiResp *CTEUserSetJSON,
	resp *resource.ReadResponse,
) {
	state.ID = types.StringValue(apiResp.ID)
	state.URI = types.StringValue(apiResp.URI)
	state.Account = types.StringValue(apiResp.Account)
	state.DevAccount = types.StringValue(apiResp.DevAccount)
	state.Application = types.StringValue(apiResp.Application)
	state.Name = types.StringValue(apiResp.Name)

	if apiResp.Description != "" {
		state.Description = types.StringValue(apiResp.Description)
	} else {
		state.Description = types.StringNull()
	}

	// Labels
	labelsMap := map[string]attr.Value{}
	for k, v := range apiResp.Labels {
		if strVal, ok := v.(string); ok {
			labelsMap[k] = types.StringValue(strVal)
		}
	}
	labelsValue, diags := types.MapValue(types.StringType, labelsMap)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Labels = labelsValue

	// Users
	var users []CTEUserTFSDK
	for _, user := range apiResp.Users {
		userObj := CTEUserTFSDK{
			OSDomain: types.StringValue(user.OSDomain),
		}
		if user.GName != "" {
			userObj.GName = types.StringValue(user.GName)
		} else {
			userObj.GName = types.StringNull()
		}
		if user.UName != "" {
			userObj.UName = types.StringValue(user.UName)
		} else {
			userObj.UName = types.StringNull()
		}
		if user.GID != nil {
			userObj.GID = types.Int64Value(int64(*user.GID))
		} else {
			userObj.GID = types.Int64Null()
		}

		if user.UID != nil {
			userObj.UID = types.Int64Value(int64(*user.UID))
		} else {
			userObj.UID = types.Int64Null()
		}

		users = append(users, userObj)
	}
	state.Users = users
}

func (r *resourceCTEUserSet) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_cte_user_set.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_cte_user_set.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
