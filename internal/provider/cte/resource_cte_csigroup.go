package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &resourceCTECSIGroup{}
	_ resource.ResourceWithConfigure   = &resourceCTECSIGroup{}
	_ resource.ResourceWithImportState = &resourceCTECSIGroup{}
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
						"update-guard-policies"}...),
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
				Computed:    true,
				Default:     stringdefault.StaticString("DefaultClientProfile"),
				Description: "Optional Client Profile for the storage group. If not provided, the default profile will be used.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "Optional description for the storage group.",
			},
			"guard_policies": schema.MapNestedAttribute{
				Optional: true,
				Computed: true,
				Default: mapdefault.StaticValue(types.MapValueMust(
					types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"guard_enabled": types.BoolType,
							"gp_id":         types.StringType,
						},
					},
					map[string]attr.Value{},
				)),
				Description: "Guard policies keyed by policy name or UUID. Eliminates index-based drift.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"guard_enabled": schema.BoolAttribute{
							Optional:    true,
							Computed:    true,
							Default:     booldefault.StaticBool(true),
							Description: "Whether this guard policy is enabled. Defaults to true.",
						},
						"gp_id": schema.StringAttribute{
							Computed:    true,
							Description: "Guardpoint ID returned by the API after the policy is added.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
					},
				},
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

	// --- Add guard policies if declared ----------------------------------
	if len(plan.GuardPolicies) > 0 {
		var gpPayload CTECSIGroupJSON
		for policyID := range plan.GuardPolicies {
			gpPayload.PolicyList = append(gpPayload.PolicyList, policyID)
		}
		gpPayloadJSON, err := json.Marshal(gpPayload)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> Create]["+id+"]")
			resp.Diagnostics.AddError("Invalid data input: CSIGroup Add Guard Policies", err.Error())
			return
		}

		gpResponse, err := r.client.PostDataV2(
			ctx,
			id,
			common.URL_CTE_CSIGROUP+"/"+plan.ID.ValueString()+"/guardpoints",
			gpPayloadJSON,
		)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> Create]["+id+"]")
			resp.Diagnostics.AddError(
				"Error adding guard policies to CSIGroup on CipherTrust Manager: ",
				"Could not add guard policies, unexpected error: "+err.Error(),
			)
			return
		}

		// Parse the guardpoints response and write gp_id + guard_enabled
		// back into each matching plan entry.
		var gpAPIResponse CTECSIGroupGuardPointsResponseJSON
		if err := json.Unmarshal([]byte(gpResponse), &gpAPIResponse); err != nil {
			resp.Diagnostics.AddError("Error parsing guardpoints response", err.Error())
			return
		}

		for _, item := range gpAPIResponse.GuardPoints {
			policyName := item.GuardPoint.PolicyName
			if entry, ok := plan.GuardPolicies[policyName]; ok {
				entry.GPID = types.StringValue(item.GuardPoint.ID)
				entry.GuardEnabled = types.BoolValue(item.GuardPoint.GuardEnabled)
				plan.GuardPolicies[policyName] = entry
			}
		}
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_csigroup.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTECSIGroup) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_csigroup.go -> Read]["+id+"]")

	var state CTECSIGroupTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get CSI Group details
	groupResponse, _ := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_CTE_CSIGROUP)
	if groupResponse == "" {
		resp.State.RemoveResource(ctx)
		return
	}

	// Parse group response into state
	var groupJSON CTECSIGroupListJSON
	if err := json.Unmarshal([]byte(groupResponse), &groupJSON); err != nil {
		resp.Diagnostics.AddError("Error parsing CSI Group response", err.Error())
		return
	}
	state.Description = types.StringValue(groupJSON.Description)
	state.ClientProfile = types.StringValue(groupJSON.ClientProfileName)
	state.Name = types.StringValue(groupJSON.Name)
	state.Namespace = types.StringValue(groupJSON.K8sNamespace)
	state.StorageClass = types.StringValue(groupJSON.K8sStorageClass)

	// Get guard policies
	gpResponse, err := r.client.GetById(
		ctx,
		id,
		state.ID.ValueString()+"/guardpoints",
		common.URL_CTE_CSIGROUP,
	)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CSI Group guard policies on CipherTrust Manager:",
			"Could not read guard policies for CSI Group id: "+state.ID.ValueString()+" unexpected error: "+err.Error(),
		)
		return
	}

	// Parse guardpoints response
	var gpListJSON CTECSIGroupGuardPointsListJSON
	if err := json.Unmarshal([]byte(gpResponse), &gpListJSON); err != nil {
		resp.Diagnostics.AddError("Error parsing guardpoints list response", err.Error())
		return
	}

	apiByGPID := make(map[string]CTECSIGuardPointJSON)
	for _, gp := range gpListJSON.Resources {
		apiByGPID[gp.ID] = gp
	}

	// Build a lookup from gp_id → existing state entry
	stateByGPID := make(map[string]CSIGroupGuardPolicyTFSDK)
	for _, gp := range state.GuardPolicies {
		stateByGPID[gp.GPID.ValueString()] = gp
	}

	refreshedPolicies := make(map[string]CSIGroupGuardPolicyTFSDK)

	// Carry over state entries that still exist in the API response
	for policyID, stateEntry := range state.GuardPolicies {
		if apiEntry, ok := apiByGPID[stateEntry.GPID.ValueString()]; ok {
			refreshedPolicies[policyID] = CSIGroupGuardPolicyTFSDK{
				GPID:         types.StringValue(apiEntry.ID),
				GuardEnabled: types.BoolValue(apiEntry.GuardEnabled),
			}
		}
		// if not found in API, the policy was removed out-of-band; drop it from state
	}

	// Add any API entries not tracked in state (added out-of-band)
	for _, apiEntry := range gpListJSON.Resources {
		if _, exists := stateByGPID[apiEntry.ID]; !exists {
			refreshedPolicies[apiEntry.PolicyName] = CSIGroupGuardPolicyTFSDK{
				GPID:         types.StringValue(apiEntry.ID),
				GuardEnabled: types.BoolValue(apiEntry.GuardEnabled),
			}
		}
	}

	state.GuardPolicies = refreshedPolicies

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_csigroup.go -> Read]["+id+"]")
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTECSIGroup) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTECSIGroupTFSDK
	var payload CTECSIGroupJSON

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
		resp.Diagnostics.AddError("Cannot change CSI group name once it is created", "Name is an immutable field")
		return
	}
	if plan.Namespace.ValueString() != state.Namespace.ValueString() {
		resp.Diagnostics.AddError("Cannot change CSI group namespace once it is created", "Namespace is an immutable field")
		return
	}
	if plan.StorageClass.ValueString() != state.StorageClass.ValueString() {
		resp.Diagnostics.AddError("Cannot change CSI group storage class once it is created", "Storage class is an immutable field")
		return
	}
	if plan.OpType.ValueString() != "" {
		if plan.OpType.ValueString() == "update" {
			if !reflect.DeepEqual(plan.GuardPolicies, state.GuardPolicies) {
				resp.Diagnostics.AddError("Cannot change guard policies using op_type = update.", "Use op_type = update-guard-policies")
				return
			}
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
		} else if plan.OpType.ValueString() == "update-guard-policies" {
			if plan.Description.ValueString() != state.Description.ValueString() || plan.ClientProfile.ValueString() != state.ClientProfile.ValueString() {
				resp.Diagnostics.AddError("Cannot change description/Client Profile using op_type = update-guard-policies", "Use op_type = update")
				return
			}
			stateByPolicyID := state.GuardPolicies
			// Add or update
			for policyID, planEntry := range plan.GuardPolicies {
				stateEntry, exists := stateByPolicyID[policyID]

				if !exists || stateEntry.GPID.IsNull() || stateEntry.GPID.ValueString() == "" {
					// New policy — POST to guardpoints
					var addPayload CTECSIGroupJSON
					addPayload.PolicyList = []string{policyID}
					addPayloadJSON, err := json.Marshal(addPayload)
					if err != nil {
						tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> update-guard-policy]["+plan.ID.ValueString()+"]")
						resp.Diagnostics.AddError("Invalid data input: CSIGroup Add Guard Policy", err.Error())
						return
					}

					gpResponse, err := r.client.PostDataV2(
						ctx,
						plan.ID.ValueString(),
						common.URL_CTE_CSIGROUP+"/"+plan.ID.ValueString()+"/guardpoints",
						addPayloadJSON,
					)
					if err != nil {
						tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> update-guard-policy]["+plan.ID.ValueString()+"]")
						resp.Diagnostics.AddError("Error adding guard policy to CSIGroup on CipherTrust Manager: ", err.Error())
						return
					}

					var gpAPIResponse CTECSIGroupGuardPointsResponseJSON
					if err := json.Unmarshal([]byte(gpResponse), &gpAPIResponse); err != nil {
						resp.Diagnostics.AddError("Error parsing guardpoints response", err.Error())
						return
					}

					if len(gpAPIResponse.GuardPoints) > 0 {
						planEntry.GPID = types.StringValue(gpAPIResponse.GuardPoints[0].GuardPoint.ID)
						planEntry.GuardEnabled = types.BoolValue(gpAPIResponse.GuardPoints[0].GuardPoint.GuardEnabled)
						plan.GuardPolicies[policyID] = planEntry
					}
					tflog.Debug(ctx, "Added guard policy: "+policyID)

				} else {
					// Existing policy — carry over gp_id from state
					planEntry.GPID = stateEntry.GPID
					plan.GuardPolicies[policyID] = planEntry

					// Only PATCH if guard_enabled changed
					if planEntry.GuardEnabled.ValueBool() == stateEntry.GuardEnabled.ValueBool() {
						tflog.Debug(ctx, "Guard policy unchanged, skipping PATCH: "+stateEntry.GPID.ValueString())
						continue
					}

					updatePayload := CTECSIGroupJSON{GuardEnabled: planEntry.GuardEnabled.ValueBool()}
					updatePayloadJSON, err := json.Marshal(updatePayload)
					if err != nil {
						tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> update-guard-policy]["+plan.ID.ValueString()+"]")
						resp.Diagnostics.AddError("Invalid data input: CSIGroup Update Guard Policy", err.Error())
						return
					}

					apiURL := fmt.Sprintf("%s/guardpoints", common.URL_CTE_CSIGROUP)
					_, err = r.client.UpdateDataV2(ctx, stateEntry.GPID.ValueString(), apiURL, updatePayloadJSON)
					if err != nil {
						tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> update-guard-policy]["+plan.ID.ValueString()+"]")
						resp.Diagnostics.AddError("Error updating guard policy on CipherTrust Manager: ", err.Error())
						return
					}
					tflog.Debug(ctx, "Updated guard policy: "+stateEntry.GPID.ValueString())
				}
			}

			//handle delete
			for policyID, stateEntry := range stateByPolicyID {
				if _, stillPresent := plan.GuardPolicies[policyID]; !stillPresent {
					_, err := r.client.DeleteByURL(
						ctx,
						plan.ID.ValueString(),
						common.URL_CTE_CSIGROUP+"/guardpoints/"+stateEntry.GPID.ValueString(),
					)
					if err != nil {
						tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_csigroup.go -> remove-guard-policy]["+plan.ID.ValueString()+"]")
						resp.Diagnostics.AddError("Error removing guard policy from CSIGroup on CipherTrust Manager: ", err.Error())
						return
					}
					tflog.Debug(ctx, "Deleted guard policy: "+stateEntry.GPID.ValueString())
				}
			}
		}
	} else {
		resp.Diagnostics.AddError(
			"op_type is a required",
			"The 'op_type' attribute must be provided during update.",
		)
		return
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

func (r *resourceCTECSIGroup) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_cte_csigroup.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_cte_csigroup.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
