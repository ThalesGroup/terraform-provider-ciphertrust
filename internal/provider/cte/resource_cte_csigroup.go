package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCTECSIGroup{}
	_ resource.ResourceWithConfigure = &resourceCTECSIGroup{}
)

func NewResourceCTECSIGroup() resource.Resource {
	return &resourceCTECSIGroup{}
}

type resourceCTECSIGroup struct {
	client *common.Client
}

func (r *resourceCTECSIGroup) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_csigroup"
}

// Schema defines the schema for the resource.
func (r *resourceCTECSIGroup) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "This section contains APIs for managing Storage Group resources related to Kubernetes Container Storage Interface (CSI).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of this resource.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"op_type": schema.StringAttribute{
				Optional:    true,
				Description: "Update CSIGroup Option",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"update",
						"add-clients",
						"remove-client",
						"add-guard-policies",
						"update-guard-policy",
						"remove-guard-policy"}...),
				},
			},
			"kubernetes_namespace": schema.StringAttribute{
				Required:    true,
				Description: "Name of the K8s namespace.",
			},
			"kubernetes_storage_class": schema.StringAttribute{
				Required:    true,
				Description: "Name of the K8s StorageClass.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name to uniquely identify the CSI storage group. This name will be visible on the CipherTrust Manager.",
			},
			"client_profile": schema.StringAttribute{
				Optional:    true,
				Description: "Optional Client Profile for the storage group. If not provided, the default profile will be used.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Optional description for the storage group.",
			},
			// Add clients to the group
			"client_list": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of identifiers of clients to be associated with the client group. This identifier can be the name or UUID.",
			},
			// Add GuardPolicy to Storage Group
			"policy_list": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of CSI policy identifiers to be associated with the storage group. This identifier can be the name or UUID.",
			},
			// Remove client from the group
			"client_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the client to be removed from the client group.",
			},
			//Update GuardPolicy in Storage Group
			"gp_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the guard policy to be updated in the client group.",
			},
			"guard_enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Enable or disable the GuardPolicy. Set to true to enable, false to disable.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTECSIGroup) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_csigroup.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTECSIGroupTFSDK
	var payload CTECSIGroupJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Namespace = common.TrimString(plan.Namespace.String())
	payload.StorageClass = common.TrimString(plan.StorageClass.String())
	payload.Name = common.TrimString(plan.Name.String())

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}
	if plan.ClientProfile.ValueString() != "" && plan.ClientProfile.ValueString() != types.StringNull().ValueString() {
		payload.ClientProfile = common.TrimString(plan.ClientProfile.String())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CSIGroup Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, common.URL_CTE_CSIGROUP, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CSIGroup  on CipherTrust Manager: ",
			"Could not create CSIGroup, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_csigroup.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTECSIGroup) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTECSIGroup) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CTECSIGroupTFSDK
	var payload CTECSIGroupJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.OpType.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		if plan.OpType.ValueString() == "update" {
			if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
				payload.Description = common.TrimString(plan.Description.String())
			}
			if plan.ClientProfile.ValueString() != "" && plan.ClientProfile.ValueString() != types.StringNull().ValueString() {
				payload.ClientProfile = common.TrimString(plan.ClientProfile.String())
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> Update]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: CTE Process Set Update",
					err.Error(),
				)
				return
			}

			response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), common.URL_CTE_CSIGROUP, payloadJSON, "id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> Update]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error creating CTE Process Set on CipherTrust Manager: ",
					"Could not create CTE Process Set, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.OpType.ValueString() == "add-clients" {
			var clientsArr []string
			for _, client := range plan.ClientList {
				clientsArr = append(clientsArr, client.ValueString())
			}
			payload.ClientList = clientsArr

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> add-clients]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: CTE CSIStorageGroup Add Clients",
					err.Error(),
				)
				return
			}

			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CSIGROUP+"/"+plan.ID.ValueString()+"/clients",
				payloadJSON,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> add-clients]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating CTE CSIStorageGroup on CipherTrust Manager: ",
					"Could not update CTE CSIStorageGroup, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.OpType.ValueString() == "remove-client" {
			response, err := r.client.DeleteByURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CSIGROUP+"/"+plan.ID.ValueString()+"/clients/"+plan.ClientID.ValueString())
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> remove-client]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error removing client from CTE CSIStorageGroup on CipherTrust Manager: ",
					"Could not remove client from the CTE CSIStorageGroup, unexpected error: "+err.Error(),
				)
				return
			}
			tflog.Debug(ctx, "[resource_cte_clientgroup.go -> remove-client -> Output]["+types.StringValue(response).String()+"]")
		} else if plan.OpType.ValueString() == "add-guard-policies" {
			var policiesArr []string
			for _, policy := range plan.PolicyList {
				policiesArr = append(policiesArr, policy.ValueString())
			}
			payload.PolicyList = policiesArr

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> add-guard-policies]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: CTE CSIStorageGroup Add GuardPolicies",
					err.Error(),
				)
				return
			}

			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CSIGROUP+"/"+plan.ID.ValueString()+"/guardpoints",
				payloadJSON,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> add-guard-policies]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating CTE CSIStorageGroup on CipherTrust Manager: ",
					"Could not update CTE CSIStorageGroup, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.OpType.ValueString() == "update-guard-policy" {
			if plan.GuardEnabled.ValueBool() != types.BoolNull().ValueBool() {
				payload.GuardEnabled = plan.GuardEnabled.ValueBool()
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> update-guard-policy]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: CTE CSIStorageGroup Update GuardPolicies",
					err.Error(),
				)
				return
			}

			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CSIGROUP+"/guardpoints"+"/"+plan.GPID.ValueString(),
				payloadJSON,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> update-guard-policy]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating CTE CSIStorageGroup on CipherTrust Manager: ",
					"Could not update CTE CSIStorageGroup, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.OpType.ValueString() == "remove-guard-policy" {
			response, err := r.client.DeleteByURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_CTE_CSIGROUP+"/guardpoints/"+plan.GPID.ValueString())
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_clientgroup.go -> remove-guard-policy]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error removing guard policy from CTE CSIStorageGroup on CipherTrust Manager: ",
					"Could not remove guard policy from the CTE CSIStorageGroup, unexpected error: "+err.Error(),
				)
				return
			}
			tflog.Debug(ctx, "[resource_cte_clientgroup.go -> remove-client -> Output]["+types.StringValue(response).String()+"]")
		} else {
			resp.Diagnostics.AddError(
				"op_type is a required",
				"The 'op_type' attribute must be provided during update.",
			)
			return
		}
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTECSIGroup) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTECSIGroupTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing CSI StorageGroup
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_CSIGROUP, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_csigroup.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE CSISecurityGroup",
			"Could not delete CSISecurityGroup, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTECSIGroup) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
