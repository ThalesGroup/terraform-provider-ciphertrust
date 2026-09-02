package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &resourceCMDomain{}
	_ resource.ResourceWithConfigure      = &resourceCMDomain{}
	_ resource.ResourceWithValidateConfig = &resourceCMDomain{}
)

func NewResourceCMDomain() resource.Resource {
	return &resourceCMDomain{}
}

type resourceCMDomain struct {
	client *common.Client
}

func (r *resourceCMDomain) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_domain"
}

func (r *resourceCMDomain) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_domain", resp)
}

// Schema defines the schema for the resource.
func (r *resourceCMDomain) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a CipherTrust Manager domain (a tenant boundary inside a single CipherTrust Manager instance). **Only available on CipherTrust Manager — not supported on CDSPaaS, where each customer is their own tenant and domains are managed by the platform.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique identifier of the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"admins": schema.ListAttribute{
				Required:    true,
				Description: "(Immutable) List of administrators for the domain",
				ElementType: types.StringType,
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1), // CM rejects an empty list with HTTP 400
				},
				PlanModifiers: []planmodifier.List{
					modifiers.ImmutableList(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) The name of the domain",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1), // CM rejects an empty name with HTTP 422
				},
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"allow_user_management": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Immutable) To allow user creation and management in the domain, set it to true. The default value is false.",
				PlanModifiers: []planmodifier.Bool{
					modifiers.UseStateForNullOrUnknownBool(),
					modifiers.ImmutableBool(),
				},
			},
			"hsm_connection_id": schema.StringAttribute{
				Optional:    true,
				Description: "The ID of the HSM connection. Required for HSM-anchored domains.",
			},
			"hsm_kek_label": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Optional name field for the domain KEK for an HSM-anchored domain. If not provided, a random UUID is assigned for KEK label. Computed to prevent plan-time drift.",
				PlanModifiers: []planmodifier.String{
					modifiers.UseStateForNullOrUnknownString(),
				},
			},
			"meta_data": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional end-user or service data stored with the domain. Should be JSON-serializable.",
			},
			"parent_ca_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Immutable) This optional parameter is the ID or URI of the parent domain's CA. This CA is used for signing the default CA of a newly created sub-domain. The oldest CA in the parent domain is used if this value is not supplied. Computed to prevent plan-time drift.",
				PlanModifiers: []planmodifier.String{
					modifiers.UseStateForNullOrUnknownString(),
					modifiers.ImmutableString(),
				},
			},
			"uri": schema.StringAttribute{
				Computed:    true,
				Description: "A human readable unique identifier of the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"account": schema.StringAttribute{
				Computed:    true,
				Description: "The account which owns this resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"application": schema.StringAttribute{
				Computed:    true,
				Description: "The application this resource belongs to.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dev_account": schema.StringAttribute{
				Computed:    true,
				Description: "The developer account which owns this resource's application.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the resource was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the resource was last updated.",
				// No UseStateForUnknown — CM writes a new timestamp on every successful PATCH.
				// Showing (known after apply) during a pre-update plan is accurate, not spurious.
				// Matches the intentional pattern on ciphertrust_scp_connection and ciphertrust_interface.
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMDomain) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cm_domain.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan CMDomainTFSDK
	var payload CMDomainJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = plan.Name.ValueString()

	var admins []string
	for _, str := range plan.Admins {
		admins = append(admins, str.ValueString())
	}
	sort.Strings(admins)
	payload.Admins = admins
	var sortedPlanAdmins []types.String
	for _, admin := range admins {
		sortedPlanAdmins = append(sortedPlanAdmins, types.StringValue(admin))
	}
	plan.Admins = sortedPlanAdmins

	if !plan.AllowUserManagement.IsNull() && !plan.AllowUserManagement.IsUnknown() {
		val := plan.AllowUserManagement.ValueBool()
		payload.AllowUserManagement = &val
	}
	if plan.HSMConnectionId.ValueString() != "" && plan.HSMConnectionId.ValueString() != types.StringNull().ValueString() {
		payload.HSMConnectionId = plan.HSMConnectionId.ValueString()
	}
	if plan.HSMKEKLabel.ValueString() != "" && plan.HSMKEKLabel.ValueString() != types.StringNull().ValueString() {
		payload.HSMKEKLabel = plan.HSMKEKLabel.ValueString()
	}
	if plan.ParentCAId.ValueString() != "" && plan.ParentCAId.ValueString() != types.StringNull().ValueString() {
		payload.ParentCAId = plan.ParentCAId.ValueString()
	}

	if !plan.Meta.IsNull() && !plan.Meta.IsUnknown() {
		metadataPayload := make(map[string]interface{})
		for k, v := range plan.Meta.Elements() {
			metadataPayload[k] = v.(types.String).ValueString()
		}
		payload.Meta = metadataPayload
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_group.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: Domain Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_DOMAIN, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_group.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating domain on CipherTrust Manager: ",
			"Could not create domain, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	if r := gjson.Get(response, "allow_user_management"); r.Exists() {
		plan.AllowUserManagement = types.BoolValue(r.Bool())
	} else {
		plan.AllowUserManagement = types.BoolNull()
	}

	// Handle optional fields - set to null if empty string to avoid inconsistent state
	hsmConnectionIdResp := gjson.Get(response, "hsm_connection_id").String()
	if hsmConnectionIdResp == "" {
		plan.HSMConnectionId = types.StringNull()
	} else {
		plan.HSMConnectionId = types.StringValue(hsmConnectionIdResp)
	}

	hsmKekLabelResp := gjson.Get(response, "hsm_kek_label").String()
	if hsmKekLabelResp == "" {
		plan.HSMKEKLabel = types.StringNull()
	} else {
		plan.HSMKEKLabel = types.StringValue(hsmKekLabelResp)
	}

	// parent_ca_id: CM never returns this field in the 201 create response (write-only input).
	// When the user configured a value, preserve it — nullifying would crash with
	// "Provider produced inconsistent result after apply" (TFIN-539).
	// When the user did not configure it (plan is null/unknown), set null explicitly
	// so the framework's post-create consistency check is satisfied.
	if r := gjson.Get(response, "parent_ca_id"); r.Exists() && r.String() != "" {
		plan.ParentCAId = types.StringValue(r.String())
	} else if plan.ParentCAId.IsNull() || plan.ParentCAId.IsUnknown() {
		plan.ParentCAId = types.StringNull()
	}
	// else: plan holds the user's configured value — preserve it.

	r.client.Log.Debug("[resource_cm_domain.go -> Create Output][" + response + "]")

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_domain.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMDomain) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMDomainTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_DOMAIN)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddError(
				fmt.Sprintf(common.NotFoundReadErrorSummaryFmt, "CM Domain"),
				fmt.Sprintf(common.NotFoundReadErrorDetailFmt, "CM Domain", state.ID.ValueString()),
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_domain.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading CM Domain on CipherTrust Manager: ",
			"Could not read CM Domain id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())

	// Handle optional fields - set to null if empty string to avoid inconsistent state
	hsmConnectionId := gjson.Get(response, "hsm_connection_id").String()
	if hsmConnectionId == "" {
		state.HSMConnectionId = types.StringNull()
	} else {
		state.HSMConnectionId = types.StringValue(hsmConnectionId)
	}

	hsmKekLabel := gjson.Get(response, "hsm_kek_label").String()
	if hsmKekLabel == "" {
		state.HSMKEKLabel = types.StringNull()
	} else {
		state.HSMKEKLabel = types.StringValue(hsmKekLabel)
	}

	// parent_ca_id: CM does not return this field in GET responses (write-only input field).
	// Preserve prior state to prevent perpetual drift after initial create.
	if r := gjson.Get(response, "parent_ca_id"); r.Exists() && r.String() != "" {
		state.ParentCAId = types.StringValue(r.String())
	}
	// else: key absent — leave state.ParentCAId unchanged.

	if r := gjson.Get(response, "allow_user_management"); r.Exists() {
		state.AllowUserManagement = types.BoolValue(r.Bool())
	} else {
		state.AllowUserManagement = types.BoolNull()
	}
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	state.Application = types.StringValue(gjson.Get(response, "application").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())

	// Read admins list
	adminsResult := gjson.Get(response, "admins")
	if adminsResult.Exists() && adminsResult.IsArray() {
		var adminsStr []string
		for _, admin := range adminsResult.Array() {
			adminsStr = append(adminsStr, admin.String())
		}
		sort.Strings(adminsStr)
		var admins []types.String
		for _, admin := range adminsStr {
			admins = append(admins, types.StringValue(admin))
		}
		state.Admins = admins
	} else {
		// Required field — CM should always return it.
		// If omitted, preserve prior state to avoid false drift.
	}

	// Read meta_data map — three-branch with !state.Meta.IsNull() outer guard.
	// When state.Meta.IsNull() (user never configured meta_data), leave state.Meta
	// unchanged (null). CM returns "{}" for unconfigured domains; without the guard
	// that would cause perpetual null→{} drift.
	if !state.Meta.IsNull() {
		metaResult := gjson.Get(response, "meta")
		if !metaResult.Exists() {
			state.Meta = types.MapNull(types.StringType)
		} else if len(metaResult.Map()) == 0 {
			state.Meta = types.MapValueMust(types.StringType, map[string]attr.Value{})
		} else {
			metaMap := make(map[string]string)
			metaResult.ForEach(func(key, value gjson.Result) bool {
				metaMap[key.String()] = value.String()
				return true
			})
			mapValue, diags2 := types.MapValueFrom(ctx, types.StringType, metaMap)
			if diags2.HasError() {
				resp.Diagnostics.Append(diags2...)
			} else {
				state.Meta = mapValue
			}
		}
	}

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_domain.go -> Read][" + id + "]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMDomain) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cm_domain.go -> Update][" + id + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_domain.go -> Update][" + id + "]")
	var plan CMDomainTFSDK
	var state CMDomainTFSDK

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get current state to preserve computed fields
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if there are actual changes to user-controlled fields
	hasChanges := false

	// Check HSM fields
	if plan.HSMKEKLabel.ValueString() != state.HSMKEKLabel.ValueString() {
		hasChanges = true
	}
	if plan.HSMConnectionId.ValueString() != state.HSMConnectionId.ValueString() {
		hasChanges = true
	}

	// Check metadata
	if !plan.Meta.Equal(state.Meta) {
		hasChanges = true
	}

	// admins, allow_user_management, name, and parent_ca_id are immutable —
	// ImmutableList/ImmutableBool/ImmutableString modifiers block plan-time changes
	// before Update() is ever called. Do not include them in hasChanges or the
	// PATCH payload.

	// allow_user_management is not updatable via PATCH; omit from hasChanges.

	// If no changes detected, preserve existing state and return
	if !hasChanges {
		r.client.Log.Debug("[resource_cm_domain.go -> Update] No changes detected, preserving state")
		diags = resp.State.Set(ctx, plan)
		resp.Diagnostics.Append(diags...)
		return
	}

	// Build PATCH payload with only the mutable fields.
	patchMap := map[string]interface{}{}
	if !plan.HSMKEKLabel.IsNull() && !plan.HSMKEKLabel.IsUnknown() {
		patchMap["hsm_kek_label"] = plan.HSMKEKLabel.ValueString()
	}
	if !plan.HSMConnectionId.IsNull() && !plan.HSMConnectionId.IsUnknown() {
		patchMap["hsm_connection_id"] = plan.HSMConnectionId.ValueString()
	}
	if !plan.ParentCAId.IsNull() && !plan.ParentCAId.IsUnknown() {
		patchMap["parent_ca_id"] = plan.ParentCAId.ValueString()
	}
	// allow_user_management is not updatable via PATCH — CM ignores it and returns
	// the original value. Omit from the payload to prevent plan inconsistency.
	if (!plan.Meta.IsNull() && !plan.Meta.IsUnknown()) || (!state.Meta.IsNull() && !state.Meta.IsUnknown()) {
		metadataPayload := make(map[string]interface{})

		// Add/update keys present in the new plan value.
		if !plan.Meta.IsNull() && !plan.Meta.IsUnknown() {
			for k, v := range plan.Meta.Elements() {
				metadataPayload[k] = v.(types.String).ValueString()
			}
		}

		// Explicitly null out keys that existed in prior state but are absent from the
		// new plan. CM's merge-patch semantics require an explicit null to delete a key;
		// omitting the key leaves it untouched server-side.
		if !state.Meta.IsNull() && !state.Meta.IsUnknown() {
			newElements := map[string]attr.Value{}
			if !plan.Meta.IsNull() && !plan.Meta.IsUnknown() {
				newElements = plan.Meta.Elements()
			}
			for k := range state.Meta.Elements() {
				if _, exists := newElements[k]; !exists {
					metadataPayload[k] = nil
				}
			}
		}

		patchMap["meta"] = metadataPayload
	}

	payloadJSON, err := json.Marshal(patchMap)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_domain.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: Domain Update",
			err.Error(),
		)
		return
	}

	_, err = r.client.UpdateData(ctx, state.ID.ValueString(), common.URL_DOMAIN, payloadJSON, "updatedAt")
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_domain.go -> Update][" + state.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error updating domain on CipherTrust Manager: ",
			"Could not update domain, unexpected error: "+err.Error(),
		)
		return
	}

	readResponse, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_DOMAIN)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_domain.go -> Update -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading CM Domain on CipherTrust Manager after update: ",
			"Could not read CM Domain id: "+state.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	// Update plan with current computed values from API
	plan.ID = types.StringValue(gjson.Get(readResponse, "id").String())
	plan.URI = types.StringValue(gjson.Get(readResponse, "uri").String())
	plan.Account = types.StringValue(gjson.Get(readResponse, "account").String())
	plan.Application = types.StringValue(gjson.Get(readResponse, "application").String())
	plan.DevAccount = types.StringValue(gjson.Get(readResponse, "devAccount").String())
	plan.CreatedAt = types.StringValue(gjson.Get(readResponse, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(readResponse, "updatedAt").String())
	if r := gjson.Get(readResponse, "allow_user_management"); r.Exists() {
		plan.AllowUserManagement = types.BoolValue(r.Bool())
	} else {
		plan.AllowUserManagement = types.BoolNull()
	}

	// Handle optional fields - set to null if empty string to avoid inconsistent state
	hsmConnectionIdUpdate := gjson.Get(readResponse, "hsm_connection_id").String()
	if hsmConnectionIdUpdate == "" {
		plan.HSMConnectionId = types.StringNull()
	} else {
		plan.HSMConnectionId = types.StringValue(hsmConnectionIdUpdate)
	}

	hsmKekLabelUpdate := gjson.Get(readResponse, "hsm_kek_label").String()
	if hsmKekLabelUpdate == "" {
		plan.HSMKEKLabel = types.StringNull()
	} else {
		plan.HSMKEKLabel = types.StringValue(hsmKekLabelUpdate)
	}

	// parent_ca_id: CM does not return this field in GET responses (write-only, immutable).
	// Preserve the plan value (= prior state, since ImmutableString blocks changes).
	if r := gjson.Get(readResponse, "parent_ca_id"); r.Exists() && r.String() != "" {
		plan.ParentCAId = types.StringValue(r.String())
	}
	// else: key absent — leave plan.ParentCAId unchanged.

	adminsReadResult := gjson.Get(readResponse, "admins")
	if adminsReadResult.Exists() && adminsReadResult.IsArray() {
		var adminsStr []string
		for _, a := range adminsReadResult.Array() {
			adminsStr = append(adminsStr, a.String())
		}
		sort.Strings(adminsStr)
		var admins []types.String
		for _, a := range adminsStr {
			admins = append(admins, types.StringValue(a))
		}
		plan.Admins = admins
	} else {
		// Required field — CM should always return it.
		// If omitted, preserve prior state to avoid false drift.
	}

	// Post-PATCH meta_data read-back.
	if plan.Meta.IsNull() {
		// User removed meta_data from config entirely. All prior keys were sent as nil
		// in the PATCH payload above. Set state to null so the next plan sees no diff.
		plan.Meta = types.MapNull(types.StringType)
	} else if !state.Meta.IsNull() {
		// plan.Meta is non-null and state.Meta was non-null: partial clear, full clear
		// via meta_data = {}, or a key-value update. Read back from CM to get the
		// authoritative post-PATCH state.
		metaReadResult := gjson.Get(readResponse, "meta")
		if !metaReadResult.Exists() {
			plan.Meta = types.MapNull(types.StringType)
		} else if len(metaReadResult.Map()) == 0 {
			plan.Meta = types.MapValueMust(types.StringType, map[string]attr.Value{})
		} else {
			metaMap := make(map[string]string)
			metaReadResult.ForEach(func(key, value gjson.Result) bool {
				metaMap[key.String()] = value.String()
				return true
			})
			mapValue, diags2 := types.MapValueFrom(ctx, types.StringType, metaMap)
			if diags2.HasError() {
				resp.Diagnostics.Append(diags2...)
			} else {
				plan.Meta = mapValue
			}
		}
	}
	// If plan.Meta is non-null and state.Meta is null (first-time meta_data addition via
	// Update), neither branch fires and plan.Meta retains the user-configured value.
	// The next terraform refresh / Read() syncs state from CM.

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMDomain) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cm_domain.go -> Delete][" + id + "]")

	var state CMDomainTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing domain
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_DOMAIN, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_domain.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				common.NotFoundDeleteWarningSummary,
				fmt.Sprintf(common.NotFoundDeleteWarningDetailFmt, "CM Domain", state.ID.ValueString()),
			)
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Domain",
			"Could not delete domain, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMDomain) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
