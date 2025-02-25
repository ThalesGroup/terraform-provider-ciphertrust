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
	_ resource.Resource              = &resourceCTEPolicySignatureRule{}
	_ resource.ResourceWithConfigure = &resourceCTEPolicySignatureRule{}
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
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the Signature Rule created in the parent policy",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
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

	plan.SignatureRuleID = types.StringValue(parseconfig(response)[0])

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
	_, err := r.client.GetById(ctx, id, state.SignatureRuleID.ValueString(), common.URL_CTE_POLICY+"/"+state.CTEPolicyID.ValueString()+"/signaturerules")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_signaturerules.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Signature Rules on CipherTrust Manager: ",
			"Could not read Security Rule: ,"+state.SignatureRuleID.ValueString()+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_signaturerules.go -> Read]["+id+"]")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEPolicySignatureRule) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {

	var plan CTEPolicyAddSignatureRuleTFSDK
	var payload SignatureRuleJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.SignatureSetID = plan.SignatureSetList[0].ValueString()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_signaturerules.go -> Update]["+plan.SignatureRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Policy Signature Rule Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(
		ctx,
		plan.SignatureRuleID.ValueString(),
		common.URL_CTE_POLICY+"/"+plan.CTEPolicyID.ValueString()+"/signaturerules",
		payloadJSON,
		"id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_policy_signaturerules.go -> Update]["+plan.SignatureRuleID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating CTE Policy Signature Rule on CipherTrust Manager: ",
			"Could not update CTE Policy Signature Rule, unexpected error: "+err.Error(),
		)
		return
	}
	plan.SignatureRuleID = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCTEPolicySignatureRule) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEPolicyAddSignatureRuleTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_POLICY, state.CTEPolicyID.ValueString(), "signaturerules", state.SignatureRuleID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.CTEPolicyID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_policy_signaturerules.go -> Delete]["+state.SignatureRuleID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CTE Policy Signature Rule",
			"Could not delete CTE Policy Signature Rule, unexpected error: "+err.Error(),
		)
		return
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
