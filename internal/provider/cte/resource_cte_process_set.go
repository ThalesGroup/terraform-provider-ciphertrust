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
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCTEProcessSet{}
	_ resource.ResourceWithConfigure = &resourceCTEProcessSet{}
)

func NewResourceCTEProcessSet() resource.Resource {
	return &resourceCTEProcessSet{}
}

type resourceCTEProcessSet struct {
	client *common.Client
}

func (r *resourceCTEProcessSet) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_process_set"
}

// Schema defines the schema for the resource.
func (r *resourceCTEProcessSet) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A process set is a collection of processes (executables) that you want to grant or deny access to GuardPoints. This provides a way to manage processes independent of the policy. Policies can be applied to process sets, not to individual processes. Optionally, file signing can be configured to check the authenticity and integrity of executables and applications before they are allowed to access GuardPoint data. A signature set must already exist before you can configure file signing in a policy for a process set.",
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
			},
			"account": schema.StringAttribute{
				Description: "The account which owns this resource.",
				Computed:    true,
			},
			"dev_account": schema.StringAttribute{
				Description: "The developer account which owns this resource's application.",
				Computed:    true,
			},
			"application": schema.StringAttribute{
				Description: "The application this resource belongs to.",
				Computed:    true,
			},
			"created_at": schema.StringAttribute{
				Description: "Date/time the application was created",
				Computed:    true,
			},
			"updated_at": schema.StringAttribute{
				Description: "Date/time the application was updated",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "Name of the ProcessSet",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the process set.",
				Optional:    true,
			},
			"labels": schema.MapAttribute{
				Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/.\nWhen labels are provided they are merged with the resource's existing labels.\nTo remove a label, set the label's value to null.\n\"labels\": {\n\t\"critical\": null\n}\nTo remove all labels, set labels to null.\n\"labels\": null",
				ElementType: types.StringType,
				Optional:    true,
			},
			"processes": schema.ListNestedAttribute{
				Description: "List of processes to be added to the process set.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"directory": schema.StringAttribute{
							Description: "Directory of the process to be added to the process set.",
							Optional:    true,
						},
						"file": schema.StringAttribute{
							Description: "File name of the process to be added to the process set.",
							Optional:    true,
						},
						"labels": schema.MapAttribute{
							Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/. To add a label, set the label's value as follows.\n\"labels\": {\n\t\"key1\": \"value1\",\n\t\"key2\": \"value2\"\n}",
							ElementType: types.StringType,
							Optional:    true,
						},
						"resource_set_id": schema.StringAttribute{
							Description: "ID or name of the resource set to link to the process set. It is used for ransomware clients as a resources exempt.",
							Optional:    true,
						},
						"signature": schema.StringAttribute{
							Description: "ID or name of the signature set to link to the process set.",
							Optional:    true,
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEProcessSet) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_process_set.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTEProcessSetTFSDK
	var payload CTEProcessSetJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = common.TrimString(plan.Name.String())
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}
	var processes []CTEProcessJSON
	for _, process := range plan.Processes {
		var processJSON CTEProcessJSON
		if process.Directory.ValueString() != "" && process.Directory.ValueString() != types.StringNull().ValueString() {
			processJSON.Directory = string(process.Directory.ValueString())
		}
		if process.File.ValueString() != "" && process.File.ValueString() != types.StringNull().ValueString() {
			processJSON.File = string(process.File.ValueString())
		}
		if process.ResourceSetId.ValueString() != "" && process.ResourceSetId.ValueString() != types.StringNull().ValueString() {
			processJSON.ResourceSetId = string(process.ResourceSetId.ValueString())
		}
		if process.Signature.ValueString() != "" && process.Signature.ValueString() != types.StringNull().ValueString() {
			processJSON.Signature = string(process.Signature.ValueString())
		}

		labelsPayload := make(map[string]interface{})
		for k, v := range process.Labels.Elements() {
			labelsPayload[k] = v.(types.String).ValueString()
		}
		processJSON.Labels = labelsPayload

		processes = append(processes, processJSON)
	}
	payload.Processes = processes

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_process_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Process Set Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_CTE_PROCESS_SET, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_process_set.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Process Set on CipherTrust Manager: ",
			"Could not create CTE Process Set, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_process_set.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEProcessSet) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEProcessSetTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_CTE_PROCESS_SET)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_process_set.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CTE ProcessSet on CipherTrust Manager: ",
			"Could not read CTE ProcessSet id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	state.Application = types.StringValue(gjson.Get(response, "application").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Description = types.StringValue(gjson.Get(response, "description").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_process_set.go -> Read]["+id+"]")
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEProcessSet) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CTEProcessSetTFSDK
	var payload CTEProcessSetJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}
	var processes []CTEProcessJSON
	for _, process := range plan.Processes {
		var processJSON CTEProcessJSON
		if process.Directory.ValueString() != "" && process.Directory.ValueString() != types.StringNull().ValueString() {
			processJSON.Directory = string(process.Directory.ValueString())
		}
		if process.File.ValueString() != "" && process.File.ValueString() != types.StringNull().ValueString() {
			processJSON.File = string(process.File.ValueString())
		}
		if process.ResourceSetId.ValueString() != "" && process.ResourceSetId.ValueString() != types.StringNull().ValueString() {
			processJSON.ResourceSetId = string(process.ResourceSetId.ValueString())
		}
		if process.Signature.ValueString() != "" && process.Signature.ValueString() != types.StringNull().ValueString() {
			processJSON.Signature = string(process.Signature.ValueString())
		}
		processes = append(processes, processJSON)
	}
	payload.Processes = processes

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_process_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Process Set Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_CTE_PROCESS_SET, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_process_set.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Process Set on CipherTrust Manager: ",
			"Could not create CTE Process Set, unexpected error: "+err.Error(),
		)
		return
	}
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEProcessSet) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEProcessSetTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_PROCESS_SET, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_process_set.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Process Set",
			"Could not delete CTE Process Set, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEProcessSet) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
