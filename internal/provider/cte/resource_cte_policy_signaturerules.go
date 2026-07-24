package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &resourceCTEPolicySignatureRule{}
	_ resource.ResourceWithConfigure   = &resourceCTEPolicySignatureRule{}
	_ resource.ResourceWithImportState = &resourceCTEPolicySignatureRule{}
)

func NewResourceCTEPolicySignatureRule() resource.Resource {
	return &resourceCTEPolicySignatureRule{}
}

type resourceCTEPolicySignatureRule struct {
	client *common.Client
}

func (r *resourceCTEPolicySignatureRule) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_policy_signature_rule"
}

// Schema defines the schema for the resource.
func (r *resourceCTEPolicySignatureRule) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the parent policy in which Signature Rule need to be added",
			},
			"ids": schema.ListAttribute{
				Computed:    true,
				Description: "IDs of the signature rules created.",
				ElementType: types.StringType,
			},
			"signature_set_id_list": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of domainsList of identifiers of signature sets of Container_Image type for CSI Policy. The identifiers can be the Name, ID (a UUIDv4), URI, or slug of the signature sets.Only one sig set can be attached at once",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEPolicySignatureRule) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_policy_signaturerules.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTEPolicyAddSignatureRuleTFSDK
	var payload AddSignaturesToRuleJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, signature := range plan.SignatureSetList {
		payload.SignatureSets = append(payload.SignatureSets, signature.ValueString())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_signaturerules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Signature Rule Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(
		ctx,
		id,
		common.URL_CTE_POLICY+"/"+plan.CTEPolicyID.ValueString()+"/signaturerules",
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_signaturerules.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Policy Signature Rule on CipherTrust Manager: ",
			"Could not create CTE Policy Signature Rule, unexpected error: "+err.Error(),
		)
		return
	}

	var postResp SignatureRulePostResponseJSON
	if err := json.Unmarshal([]byte(response), &postResp); err != nil {
		resp.Diagnostics.AddError("Error parsing signature rule response", err.Error())
		return
	}

	// Capture all rule IDs
	var ruleIDs []attr.Value
	for _, successRule := range postResp.SuccessSignatureRules {
		ruleIDs = append(ruleIDs, types.StringValue(successRule.SignatureRule.ID))
	}

	signatureRuleIDList, diags := types.ListValue(types.StringType, ruleIDs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.SignatureRuleIDs = signatureRuleIDList

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_signaturerules.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEPolicySignatureRule) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {

	var state CTEPolicyAddSignatureRuleTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Fetch each rule by ID and refresh state
	var refreshedNames []types.String
	var refreshedIDs []attr.Value
	for _, ruleID := range state.SignatureRuleIDs.Elements() {
		ruleIDStr := ruleID.(types.String).ValueString()
		response, err := r.client.GetById(ctx, id, ruleIDStr,
			common.URL_CTE_POLICY+"/"+state.CTEPolicyID.ValueString()+"/signaturerules")
		if err != nil || response == "" {
			// Rule deleted on CM — skip it
			tflog.Debug(ctx, "Signature rule not found on CM, removing from state: "+ruleIDStr)
			continue
		}

		var apiResp SignatureRuleJSON
		if err = json.Unmarshal([]byte(response), &apiResp); err != nil {
			resp.Diagnostics.AddError("Error parsing signature rule response", err.Error())
			return
		}

		// Use signature_set_name from response
		refreshedNames = append(refreshedNames, types.StringValue(apiResp.SignatureSetName))
		refreshedIDs = append(refreshedIDs, types.StringValue(apiResp.ID))
	}

	state.SignatureSetList = refreshedNames
	if refreshedIDs == nil {
		refreshedIDs = []attr.Value{}
	}
	refreshedIDsList, listDiags := types.ListValue(types.StringType, refreshedIDs)
	resp.Diagnostics.Append(listDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.SignatureRuleIDs = refreshedIDsList

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_signaturerules.go -> Read]["+id+"]")
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)

}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicySignatureRule) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEPolicyAddSignatureRuleTFSDK

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
	if plan.CTEPolicyID.ValueString() != state.CTEPolicyID.ValueString() {
		resp.Diagnostics.AddError("Cannot change policy ID associated with policy rule", "Policy ID is an immutable field")
		return
	}

	id := uuid.New().String()

	stateIDs := state.SignatureRuleIDs.Elements()

	planLen := len(plan.SignatureSetList)
	stateLen := len(state.SignatureSetList)

	var finalRuleIDs []attr.Value

	// CASE 1:
	// STATE HAS EXTRA ITEMS -> DELETE

	if stateLen > planLen {

		for i := planLen; i < stateLen; i++ {

			ruleID := stateIDs[i].(types.String).ValueString()

			deleteURL := fmt.Sprintf(
				"%s/%s/%s/signaturerules/%s",
				r.client.CipherTrustURL,
				common.URL_CTE_POLICY,
				state.CTEPolicyID.ValueString(),
				ruleID,
			)

			_, err := r.client.DeleteByID(
				ctx,
				"DELETE",
				ruleID,
				deleteURL,
				nil,
			)

			if err != nil {
				resp.Diagnostics.AddError(
					"Error deleting signature rule",
					err.Error(),
				)
				return
			}

			tflog.Debug(
				ctx,
				"Deleted signature rule: "+ruleID,
			)
		}
	}

	// ------------------------------------------------------------
	// CASE 2:
	// Handle indices present in BOTH state and plan
	// ------------------------------------------------------------

	commonLen := min(planLen, stateLen)

	for i := 0; i < commonLen; i++ {

		planName := plan.SignatureSetList[i].ValueString()
		stateName := state.SignatureSetList[i].ValueString()

		ruleID := stateIDs[i].(types.String).ValueString()
		// UNCHANGED
		if planName == stateName {

			finalRuleIDs = append(finalRuleIDs, types.StringValue(ruleID))

			continue
		}

		// PATCH UPDATED RULE
		patchEndpoint := fmt.Sprintf(
			"%s/%s/signaturerules",
			common.URL_CTE_POLICY,
			state.CTEPolicyID.ValueString(),
		)

		patchPayload := SignatureRuleJSON{
			SignatureSetID: planName,
		}

		patchPayloadJSON, err := json.Marshal(patchPayload)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error marshalling patch payload",
				err.Error(),
			)
			return
		}

		_, err = r.client.UpdateDataV2(
			ctx,
			ruleID,
			patchEndpoint,
			patchPayloadJSON,
		)

		if err != nil {
			resp.Diagnostics.AddError(
				"Error patching signature rule",
				err.Error(),
			)
			return
		}

		tflog.Debug(
			ctx,
			fmt.Sprintf(
				"Patched signature rule %s from %s to %s",
				ruleID,
				stateName,
				planName,
			),
		)

		finalRuleIDs = append(finalRuleIDs, types.StringValue(ruleID))
	}

	// CASE 3:
	// PLAN HAS EXTRA ITEMS -> CREATE

	if planLen > stateLen {

		ruleEndpoint := fmt.Sprintf(
			"%s/%s/signaturerules",
			common.URL_CTE_POLICY,
			state.CTEPolicyID.ValueString(),
		)

		for i := stateLen; i < planLen; i++ {

			planName := plan.SignatureSetList[i].ValueString()

			rulePayload := AddSignaturesToRuleJSON{
				SignatureSets: []string{planName},
			}

			rulePayloadJSON, err := json.Marshal(rulePayload)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error marshalling create payload",
					err.Error(),
				)
				return
			}

			response, err := r.client.PostDataV2(
				ctx,
				id,
				ruleEndpoint,
				rulePayloadJSON,
			)

			if err != nil {
				resp.Diagnostics.AddError(
					"Error creating signature rule",
					err.Error(),
				)
				return
			}

			var postResp SignatureRulePostResponseJSON

			err = json.Unmarshal([]byte(response), &postResp)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error parsing create response",
					err.Error(),
				)
				return
			}

			if len(postResp.SuccessSignatureRules) > 0 {

				newRuleID := postResp.SuccessSignatureRules[0].SignatureRule.ID

				finalRuleIDs = append(
					finalRuleIDs,
					types.StringValue(newRuleID),
				)

				tflog.Debug(
					ctx,
					"Created signature rule: "+newRuleID,
				)
			}
		}
	}

	// ------------------------------------------------------------
	// SAVE UPDATED IDS
	// ------------------------------------------------------------

	if finalRuleIDs == nil {
		finalRuleIDs = []attr.Value{}
	}

	finalRuleIDsList, listDiags := types.ListValue(
		types.StringType,
		finalRuleIDs,
	)

	resp.Diagnostics.Append(listDiags...)

	if resp.Diagnostics.HasError() {
		return
	}

	plan.SignatureRuleIDs = finalRuleIDsList

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEPolicySignatureRule) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEPolicyAddSignatureRuleTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete all signature rules using .Elements() for types.List
	for _, ruleID := range state.SignatureRuleIDs.Elements() {
		ruleIDStr := ruleID.(types.String).ValueString()
		url := fmt.Sprintf("%s/%s/%s/signaturerules/%s",
			r.client.CipherTrustURL,
			common.URL_CTE_POLICY,
			state.CTEPolicyID.ValueString(),
			ruleIDStr,
		)
		_, err := r.client.DeleteByID(ctx, "DELETE", ruleIDStr, url, nil)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Deleting Signature Rule",
				"Could not delete signature rule "+ruleIDStr+": "+err.Error(),
			)
			return
		}
		tflog.Debug(ctx, "Deleted signature rule: "+ruleIDStr)
	}

}

func (d *resourceCTEPolicySignatureRule) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func parseconfig(response string) []string {
	var ids []string
	SuccessSize := int((gjson.Get(response, "success_signature_rules.#")).Int())

	k := 0
	for k < SuccessSize {
		ids = append(ids, gjson.Get(string(response), fmt.Sprintf("success_signature_rules.%d.signature_rule.id", k)).String())
		k++
	}
	return ids
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func (r *resourceCTEPolicySignatureRule) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID format: "policy_id:signature_rule_id"
	parts := strings.Split(req.ID, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			"Expected format: policy_id:signature_rule_id",
		)
		return
	}

	policyID := parts[0]
	ruleID := parts[1]

	idsList, diags := types.ListValue(types.StringType, []attr.Value{types.StringValue(ruleID)})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := CTEPolicyAddSignatureRuleTFSDK{
		CTEPolicyID:      types.StringValue(policyID),
		SignatureRuleIDs: idsList,
		SignatureSetList: []types.String{},
	}

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}
