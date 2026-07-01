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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &resourceCTEResourceSet{}
	_ resource.ResourceWithConfigure   = &resourceCTEResourceSet{}
	_ resource.ResourceWithImportState = &resourceCTEResourceSet{}
)

func NewResourceCTEResourceSet() resource.Resource {
	return &resourceCTEResourceSet{}
}

type resourceCTEResourceSet struct {
	client *common.Client
}

func (r *resourceCTEResourceSet) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_resource_set"
}

// Schema defines the schema for the resource.
func (r *resourceCTEResourceSet) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A resource is a combination of a directory, a file, and patterns or special variables. A resource set is a named collection of directories, files, or both, that a user or process will be permitted or denied access to.",
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
				Description: "Name of the resource set.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the resource set.",
				Optional:    true,
			},
			"labels": schema.MapAttribute{
				Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/. To add a label, set the label's value as follows.\n\"labels\": {\n\t\"key1\": \"value1\",\n\t\"key2\": \"value2\"\n}",
				ElementType: types.StringType,
				Default: mapdefault.StaticValue(
					types.MapValueMust(types.StringType, map[string]attr.Value{}),
				),
				Optional: true,
				Computed: true,
			},
			"type": schema.StringAttribute{
				Description: "Type of the resource set. The valid options is Directory. The default value is Directory.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("Directory"),
			},
			"resources": schema.ListNestedAttribute{
				Description: "List of resources to be added to the resource set.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"directory": schema.StringAttribute{
							Description: "Directory of the resource to be added to the resource set.",
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(""),
						},
						"file": schema.StringAttribute{
							Description: "File name of the resource to be added to the resource set.",
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(""),
						},
						"hdfs": schema.BoolAttribute{
							Description: "Whether the specified path is a HDFS path.",
							Optional:    true,
							Computed:    true,
							Default:     booldefault.StaticBool(false),
						},
						"include_subfolders": schema.BoolAttribute{
							Description: "Whether to include subfolders to the resource.",
							Optional:    true,
							Computed:    true,
							Default:     booldefault.StaticBool(false),
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEResourceSet) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_resource_set.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTEResourceSetTFSDK
	var payload CTEResourceSetJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = common.TrimString(plan.Name.String())
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}
	if plan.Type.ValueString() != "" && plan.Type.ValueString() != types.StringNull().ValueString() {
		payload.Type = common.TrimString(plan.Type.String())
	} else {
		payload.Type = "Directory"
	}

	var resources []CTEResourceJSON
	for _, resource := range plan.Resources {
		var resourceJSON CTEResourceJSON
		if resource.Directory.ValueString() != "" && resource.Directory.ValueString() != types.StringNull().ValueString() {
			resourceJSON.Directory = string(resource.Directory.ValueString())
		}
		if resource.File.ValueString() != "" && resource.File.ValueString() != types.StringNull().ValueString() {
			resourceJSON.File = string(resource.File.ValueString())
		}
		if resource.HDFS.ValueBool() != types.BoolNull().ValueBool() {
			resourceJSON.HDFS = bool(resource.HDFS.ValueBool())
		}
		if resource.IncludeSubfolders.ValueBool() != types.BoolNull().ValueBool() {
			resourceJSON.IncludeSubfolders = bool(resource.IncludeSubfolders.ValueBool())
		}
		resources = append(resources, resourceJSON)
	}
	payload.Resources = resources

	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = labelsPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_resource_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Resource Set Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_CTE_RESOURCE_SET, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_resource_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Resource Set on CipherTrust Manager: ",
			"Could not create CTE Resource Set, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_resource_set.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEResourceSet) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEResourceSetTFSDK
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
	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_CTE_RESOURCE_SET)

	if response == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	var apiResp CTEResourceSetJSON

	err = json.Unmarshal([]byte(response), &apiResp)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing API response",
			err.Error(),
		)
		return
	}

	setCTEResourceSetState(&state, &apiResp, resp)

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
			"[resource_cte_resource_set.go -> Read]["+id+"]",
	)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEResourceSet) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEResourceSetTFSDK
	var payload CTEResourceSetJSON

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
	//immutable fields handling
	if plan.Name.ValueString() != state.Name.ValueString() {
		resp.Diagnostics.AddError("Cannot change resource set name once it is created", "Name is an immutable field")
		return
	}
	if plan.Type.ValueString() != state.Type.ValueString() {
		resp.Diagnostics.AddError("Cannot change resource set type", "Type is an immutable field")
		return
	}

	payload.Description = common.TrimString(plan.Description.String())

	var resources []CTEResourceJSON
	for _, resource := range plan.Resources {
		var resourceJSON CTEResourceJSON
		if resource.Directory.ValueString() != "" && resource.Directory.ValueString() != types.StringNull().ValueString() {
			resourceJSON.Directory = string(resource.Directory.ValueString())
		}
		if resource.File.ValueString() != "" && resource.File.ValueString() != types.StringNull().ValueString() {
			resourceJSON.File = string(resource.File.ValueString())
		}
		if resource.HDFS.ValueBool() != types.BoolNull().ValueBool() {
			resourceJSON.HDFS = bool(resource.HDFS.ValueBool())
		}
		if resource.IncludeSubfolders.ValueBool() != types.BoolNull().ValueBool() {
			resourceJSON.IncludeSubfolders = bool(resource.IncludeSubfolders.ValueBool())
		}
		resources = append(resources, resourceJSON)
	}
	payload.Resources = resources

	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = labelsPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_resource_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Resource Set Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_CTE_RESOURCE_SET, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_resource_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Resource Set on CipherTrust Manager: ",
			"Could not create CTE Resource Set, unexpected error: "+err.Error(),
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
func (r *resourceCTEResourceSet) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEResourceSetTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_RESOURCE_SET, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_resource_set.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Resource Set",
			"Could not delete CTE Resource Set, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEResourceSet) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func setCTEResourceSetState(
	state *CTEResourceSetTFSDK,
	apiResp *CTEResourceSetJSON,
	resp *resource.ReadResponse,
) {
	state.ID = types.StringValue(apiResp.ID)
	state.URI = types.StringValue(apiResp.URI)
	state.Account = types.StringValue(apiResp.Account)
	state.DevAccount = types.StringValue(apiResp.DevAccount)
	state.Application = types.StringValue(apiResp.Application)
	state.Name = types.StringValue(apiResp.Name)
	state.Type = types.StringValue(apiResp.Type)

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

	// Resources
	var resources []CTEResourceTFSDK
	for _, resource := range apiResp.Resources {
		resourceObj := CTEResourceTFSDK{
			Directory:         types.StringValue(resource.Directory),
			File:              types.StringValue(resource.File),
			HDFS:              types.BoolValue(resource.HDFS),
			IncludeSubfolders: types.BoolValue(resource.IncludeSubfolders),
		}
		resources = append(resources, resourceObj)
	}
	state.Resources = resources
}

func (r *resourceCTEResourceSet) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_cte_resource_set.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_cte_resource_set.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
