package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
)

var (
	_ resource.Resource                = &resourceCTEClientGP{}
	_ resource.ResourceWithConfigure   = &resourceCTEClientGP{}
	_ resource.ResourceWithImportState = &resourceCTEClientGP{}
)

func NewResourceCTEClientGP() resource.Resource {
	return &resourceCTEClientGP{}
}

type resourceCTEClientGP struct {
	client *common.Client
}

func (r *resourceCTEClientGP) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_client_guardpoint"
}

func (r *resourceCTEClientGP) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A GuardPoint specifies the list of folders that contains paths to be protected." +
			" Access to files and encryption of files under the GuardPoint is controlled by security policies." +
			" Terraform Destroy will unguard the paths.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Comma-separated list of GuardPoint IDs managed by this resource.",
			},
			"client_id": schema.StringAttribute{
				Required:    true,
				Description: "CTE Client ID.",
			},
			"guard_points": schema.MapNestedAttribute{
				Required:    true,
				Description: "Map of GuardPoints keyed by guard_path. Each key is the path to guard.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "GuardPoint ID returned by the API.",
							PlanModifiers: []planmodifier.String{
								// UseStateForUnknown() unconditionally copies the prior
								// state value once triggered. For a guard_path key that
								// does not exist yet in prior state (e.g. a newly added
								// guard_point), that state value is null (not absent),
								// which forces this attribute's planned value to a
								// concrete null instead of leaving it unknown. Terraform
								// then rejects the apply once Update() resolves it to a
								// real ID ("provider produced inconsistent result after
								// apply"). UseNonNullStateForUnknown() only copies the
								// prior value when it is non-null, so brand-new map
								// entries correctly stay "(known after apply)".
								stringplanmodifier.UseNonNullStateForUnknown(),
							},
						},
						"guard_point_params": schema.SingleNestedAttribute{
							Required:    true,
							Description: "Parameters for this GuardPoint.",
							Attributes: map[string]schema.Attribute{
								"guard_point_type": schema.StringAttribute{
									Required: true,
									Description: "Type of the GuardPoint. guard_point_type is immutable once a GuardPoint is created: " +
										"changing it for an EXISTING guard_path is rejected with a plan-time error by Update() " +
										"(see \"Cannot change guard_point_type for an existing GuardPoint\"), since CM does not " +
										"support changing it via PATCH. Adding a brand-new guard_path with any guard_point_type " +
										"does not force a replace -- it is created in place by Update().",
									PlanModifiers: []planmodifier.String{
										// TFIN-634: plain stringplanmodifier.RequiresReplace() cannot tell "a brand-new
										// guard_path (map key) was added" apart from "an existing guard_path's type
										// actually changed" -- both look like PlanValue != StateValue, since StateValue
										// is null for a map key that never existed in prior state. That made adding
										// ANY new guard point force a whole-resource -/+ replace, destroying every
										// existing (unrelated, untouched) guard point too. If Create() then failed for
										// any reason, Terraform's destroy-before-create ordering meant the destroy had
										// already completed with no rollback, permanently losing all guard points.
										// RequiresReplaceUnlessNewMapEntry only requires replace when the guard_path
										// key already existed in prior state (a genuine type change on an existing,
										// converged entry); a brand-new guard_path is instead created in place by
										// Update()'s existing "create new paths" logic, never triggering a replace.
										modifiers.RequiresReplaceUnlessNewMapEntry(),
									},
								},
								"policy_id": schema.StringAttribute{
									Required:    true,
									Description: "ID of the policy applied with this GuardPoint.",
								},
								"automount_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether automount is enabled with the GuardPoint.",
								},
								"cifs_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether to enable CIFS.",
								},
								"data_classification_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether data classification is enabled.",
								},
								"data_lineage_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether data lineage is enabled.",
								},
								"disk_name": schema.StringAttribute{
									Optional:    true,
									Description: "Name of the disk for Oracle ASM disk group.",
								},
								"diskgroup_name": schema.StringAttribute{
									Optional:    true,
									Description: "Name of the disk group for Oracle ASM.",
								},
								"early_access": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether secure start is turned on. Changing this value for an EXISTING guard_path is applied in place via a dedicated CM endpoint -- it does not force a replace.",
									// CM has a dedicated early-access endpoint that supports both
									// true->false and false->true in place for an existing
									// GuardPoint, so no plan modifier is needed. Update() calls
									// that dedicated endpoint directly on a genuine change.
								},
								"intelligent_protection": schema.BoolAttribute{
									Optional:    true,
									Description: "Flag to enable intelligent protection.",
								},
								"is_idt_capable_device": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether the device is IDT capable.",
								},
								"mfa_enabled": schema.BoolAttribute{
									Optional:    true,
									Computed:    true,
									Default:     booldefault.StaticBool(false),
									Description: "Whether MFA is enabled.",
								},
								"network_share_credentials_id": schema.StringAttribute{
									Optional:    true,
									Description: "ID of the credentials for network share.",
								},
								"preserve_sparse_regions": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether to preserve sparse file regions. CM has a dedicated endpoint that turns this off in place for an EXISTING guard_path (true -> false does not force a replace), but once turned off it can never be turned back on for that same GuardPoint via any API call -- changing it from false to true for an EXISTING guard_path forces a whole-resource replace.",
									PlanModifiers: []planmodifier.Bool{
										// See resource_cte_clientgroup_guardpoints.go's
										// preserve_sparse_regions for the full rationale -- same
										// treatment applied here for consistency between the two
										// resources.
										modifiers.BoolRequiresReplaceOnFalseToTrueUnlessNewMapEntry(),
									},
								},
								"guard_enabled": schema.BoolAttribute{
									Optional:    true,
									Computed:    true,
									Default:     booldefault.StaticBool(true),
									Description: "Whether the GuardPoint is enabled. Changing this value for an EXISTING guard_path is applied in place via a dedicated CM endpoint -- it does not force a replace.",
									// PR review follow-up: guard_enabled is create-time-inert on CM (a
									// GuardPoint created with guard_enabled = false still comes
									// up enabled) and the generic PATCH .../guardpoints/{id}
									// also silently no-ops it. Both Create() and Update() now
									// call CM's dedicated .../guardpoints/enable endpoint
									// instead, confirmed live to work in both directions
									// (true->false and false->true) for an existing GuardPoint.
									// Since Update() actually applies the change either way (same
									// reasoning as early_access above), no plan modifier is
									// needed here.
								},
							},
						},
					},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func (r *resourceCTEClientGP) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cte_client_guardpoints.go -> Create][" + id + "]")

	var plan CTEClientGuardPointTFSDK
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	type batchKey struct {
		GPType                string
		PolicyID              string
		IsAutomountEnabled    bool
		IsCIFSEnabled         bool
		IsEarlyAccessEnabled  bool
		IsDeviceIDTCapable    bool
		IsMFAEnabled          bool
		PreserveSparseRegions bool
		NWShareCredentialsID  string
		DiskName              string
		DiskgroupName         string
		// TFIN-544: these 4 fields were missing from the comparison key. Two
		// guard points differing ONLY in one of these fields used to hash to
		// the same batchKey and collapse into a single batched POST
		// /guardpoints call, so only one guard point's requested value for
		// that field actually reached CM ("first writer wins"). Same root
		// cause as TFIN-628 on the sibling resource_cte_clientgroup_guardpoints.go.
		IsGuardEnabled                 bool
		IsDataClassificationEnabled    bool
		IsDataLineageEnabled           bool
		IsIntelligentProtectionEnabled bool
	}
	type batchEntry struct {
		params     CTEClientGuardPointParamsTFSDK
		guardPaths []string // ordered list of paths in this batch
	}

	batchMap := make(map[batchKey]*batchEntry)
	var batchOrder []batchKey

	for guardPath, entry := range plan.GuardPoints {
		p := entry.GuardPointParams
		key := batchKey{
			GPType:                         p.GPType.ValueString(),
			PolicyID:                       p.PolicyID.ValueString(),
			IsAutomountEnabled:             p.IsAutomountEnabled.ValueBool(),
			IsCIFSEnabled:                  p.IsCIFSEnabled.ValueBool(),
			IsEarlyAccessEnabled:           p.IsEarlyAccessEnabled.ValueBool(),
			IsDeviceIDTCapable:             p.IsDeviceIDTCapable.ValueBool(),
			IsMFAEnabled:                   p.IsMFAEnabled.ValueBool(),
			PreserveSparseRegions:          p.PreserveSparseRegions.ValueBool(),
			NWShareCredentialsID:           p.NWShareCredentialsID.ValueString(),
			DiskName:                       p.DiskName.ValueString(),
			DiskgroupName:                  p.DiskgroupName.ValueString(),
			IsGuardEnabled:                 p.IsGuardEnabled.ValueBool(),
			IsDataClassificationEnabled:    p.IsDataClassificationEnabled.ValueBool(),
			IsDataLineageEnabled:           p.IsDataLineageEnabled.ValueBool(),
			IsIntelligentProtectionEnabled: p.IsIntelligentProtectionEnabled.ValueBool(),
		}
		if _, exists := batchMap[key]; !exists {
			batchMap[key] = &batchEntry{params: p}
			batchOrder = append(batchOrder, key)
		}
		batchMap[key].guardPaths = append(batchMap[key].guardPaths, guardPath)
	}

	// pathToID collects the API-assigned ID for each guard_path after creation.
	pathToID := make(map[string]string)

	for _, key := range batchOrder {
		entry := batchMap[key]
		p := entry.params

		paramsPayload := buildParamsPayload(p)
		payload := CTEClientGuardPointJSON{
			GuardPaths:       entry.guardPaths,
			GuardPointParams: &paramsPayload,
		}

		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_client_guardpoints.go -> Create][" + id + "]")
			resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Creation", err.Error())
			return
		}

		response, err := r.client.PostDataV2(
			ctx,
			id,
			common.URL_CTE_CLIENT+"/"+plan.CTEClientID.ValueString()+"/guardpoints",
			payloadJSON,
		)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_client_guardpoints.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Error creating CTE Client Guardpoint on CipherTrust Manager: ",
				"Could not create CTE Client Guardpoint, unexpected error: "+err.Error(),
			)
			return
		}

		// Parse IDs from the API response JSON by matching guard_path, not position.
		gpSize := int(gjson.Get(response, "guardpoints.#").Int())
		var createdIDs []string
		for i := 0; i < gpSize; i++ {
			returnedPath := gjson.Get(response, fmt.Sprintf("guardpoints.%d.guardpoint.guard_path", i)).String()
			returnedID := gjson.Get(response, fmt.Sprintf("guardpoints.%d.guardpoint.id", i)).String()
			if returnedPath != "" && returnedID != "" {
				pathToID[returnedPath] = returnedID
				createdIDs = append(createdIDs, returnedID)
			}
		}

		// PR review follow-up: guard_enabled is create-time-inert on CM -- confirmed
		// live that a GuardPoint created with guard_enabled = false still
		// comes back guard_enabled = true. Explicitly disable this batch's
		// newly created GuardPoints via the dedicated endpoint whenever the
		// plan requested guard_enabled = false.
		if !p.IsGuardEnabled.ValueBool() {
			if err := setGuardEnabled(ctx, r.client, common.URL_CTE_CLIENT+"/"+plan.CTEClientID.ValueString()+"/guardpoints/enable", createdIDs, false); err != nil {
				r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_client_guardpoints.go -> Create/GuardEnabled][" + id + "]")
				resp.Diagnostics.AddError(
					"Error disabling newly created Guardpoint(s) for client "+plan.CTEClientID.ValueString(),
					err.Error(),
				)
				return
			}
		}
	}

	// Write IDs back into the plan map and build the top-level composite ID.
	var allIDs []string
	for guardPath, entry := range plan.GuardPoints {
		gpID := pathToID[guardPath]
		entry.ID = types.StringValue(gpID)
		plan.GuardPoints[guardPath] = entry
		allIDs = append(allIDs, gpID)
	}
	sort.Strings(allIDs)
	plan.ID = types.StringValue(strings.Join(allIDs, ","))

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_client_guardpoints.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *resourceCTEClientGP) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEClientGuardPointTFSDK
	id := uuid.New().String()

	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cte_client_guardpoints.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	clientID := state.CTEClientID.ValueString()

	response, err := r.client.GetById(ctx, id, "", common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints")
	if handleReadNotFound(ctx, err, "CTE Client Guardpoints (client "+clientID+")", &resp.Diagnostics) {
		return
	}

	if response == "" {
		resp.Diagnostics.AddError(
			"CTE Client Guardpoints (client "+clientID+") not found",
			"Guardpoints for CTE Client "+clientID+" returned an empty response from CipherTrust Manager during refresh, indicating the parent client or its guardpoints may have been removed out-of-band. Keeping this resource in Terraform state rather than removing it, since this may be a transient issue or a change that should be reconciled deliberately.",
		)
		return
	}

	var envelope struct {
		Resources []CTEClientGuardPointListJSON `json:"resources"`
	}
	if err := json.Unmarshal([]byte(response), &envelope); err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_client_guardpoints.go -> Read][" + clientID + "]")
		resp.Diagnostics.AddError(
			"Error parsing Guardpoints response for Client id "+clientID,
			err.Error(),
		)
		return
	}

	if len(envelope.Resources) == 0 {
		resp.Diagnostics.AddError(
			"CTE Client Guardpoints (client "+clientID+") not found",
			"No guardpoints remain on CipherTrust Manager for CTE Client "+clientID+", indicating they may have been removed out-of-band. Keeping this resource in Terraform state rather than removing it, since this may be a transient issue or a change that should be reconciled deliberately.",
		)
		return
	}

	newGuardPoints := make(map[string]CTEClientGroupGuardPointEntryTFSDK)
	var allIDs []string

	for _, gp := range envelope.Resources {
		prevEntry, hadPrior := state.GuardPoints[gp.GuardPath]

		entry := CTEClientGroupGuardPointEntryTFSDK{
			ID: types.StringValue(gp.ID),
			GuardPointParams: CTEClientGuardPointParamsTFSDK{
				GPType:         types.StringValue(gp.GuardPointType),
				IsGuardEnabled: types.BoolValue(gp.GuardEnabled),
				// mfa_enabled is now actually sent by Update() (see the dedicated
				// payload fix above), so read it fresh from CM on every Read()
				// instead of only ever carrying forward the prior state value --
				// matching the sibling resource_cte_clientgroup_guardpoints.go's
				// Read(), which already does this.
				IsMFAEnabled: types.BoolValue(gp.MFAEnabled),
				PolicyID:     types.StringValue(gp.PolicyID),
			},
		}

		if hadPrior {
			p := prevEntry.GuardPointParams
			entry.GuardPointParams.IsAutomountEnabled = p.IsAutomountEnabled
			entry.GuardPointParams.IsCIFSEnabled = p.IsCIFSEnabled
			entry.GuardPointParams.IsEarlyAccessEnabled = p.IsEarlyAccessEnabled
			entry.GuardPointParams.IsDeviceIDTCapable = p.IsDeviceIDTCapable
			entry.GuardPointParams.PreserveSparseRegions = p.PreserveSparseRegions
			entry.GuardPointParams.IsDataClassificationEnabled = p.IsDataClassificationEnabled
			entry.GuardPointParams.IsDataLineageEnabled = p.IsDataLineageEnabled
			entry.GuardPointParams.IsIntelligentProtectionEnabled = p.IsIntelligentProtectionEnabled
			entry.GuardPointParams.NWShareCredentialsID = p.NWShareCredentialsID
			entry.GuardPointParams.DiskName = p.DiskName
			entry.GuardPointParams.DiskgroupName = p.DiskgroupName
		}

		newGuardPoints[gp.GuardPath] = entry
		allIDs = append(allIDs, gp.ID)
	}

	state.GuardPoints = newGuardPoints
	sort.Strings(allIDs)
	state.ID = types.StringValue(strings.Join(allIDs, ","))

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_client_guardpoints.go -> Read][" + id + "]")
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *resourceCTEClientGP) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEClientGuardPointTFSDK

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

	//immutable field handling for client id
	if state.CTEClientID.ValueString() != plan.CTEClientID.ValueString() {
		resp.Diagnostics.AddError("Cannot change client_id", "client_id is an immutable field")
		return
	}
	clientID := plan.CTEClientID.ValueString()

	// ---------------------------------------------------------------
	// PHASE 0 — UNGUARD guardpoints whose guard_path was removed from plan.
	// With MapNestedAttribute, a removed key == a removed guardpoint.
	// ---------------------------------------------------------------
	var removedIDs []string
	for guardPath, stateEntry := range state.GuardPoints {
		if _, stillInPlan := plan.GuardPoints[guardPath]; !stillInPlan {
			removedIDs = append(removedIDs, stateEntry.ID.ValueString())
		}
	}

	if len(removedIDs) > 0 {
		unguardPayload := CTEClientGuardPointUnguardJSON{
			GuardPointIdList: removedIDs,
		}
		unguardPayloadJSON, err := json.Marshal(unguardPayload)
		if err != nil {
			resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Unguard during Update", err.Error())
			return
		}

		_, err = r.client.UpdateData(
			ctx,
			"",
			common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints/unguard",
			unguardPayloadJSON,
			"",
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error unguarding removed Guardpoints for client "+clientID,
				err.Error(),
			)
			return
		}

		r.client.Log.Trace("[resource_cte_client_guardpoints.go -> Update/Unguard] unguarded IDs: " + strings.Join(removedIDs, ","))
	}

	// ---------------------------------------------------------------
	// PHASE 1 — CREATE guard_paths that are new in the plan (not in state).
	// ---------------------------------------------------------------
	type batchKey struct {
		GPType                string
		PolicyID              string
		IsAutomountEnabled    bool
		IsCIFSEnabled         bool
		IsEarlyAccessEnabled  bool
		IsDeviceIDTCapable    bool
		IsMFAEnabled          bool
		PreserveSparseRegions bool
		NWShareCredentialsID  string
		DiskName              string
		DiskgroupName         string
		// TFIN-544: these 4 fields were missing from the comparison key. Two
		// guard points differing ONLY in one of these fields used to hash to
		// the same batchKey and collapse into a single batched POST
		// /guardpoints call, so only one guard point's requested value for
		// that field actually reached CM ("first writer wins"). Same root
		// cause as TFIN-628 on the sibling resource_cte_clientgroup_guardpoints.go.
		IsGuardEnabled                 bool
		IsDataClassificationEnabled    bool
		IsDataLineageEnabled           bool
		IsIntelligentProtectionEnabled bool
	}
	type batchEntry struct {
		params     CTEClientGuardPointParamsTFSDK
		guardPaths []string
	}

	batchMap := make(map[batchKey]*batchEntry)
	var batchOrder []batchKey
	newPaths := make(map[string]bool) // track which paths were just created

	for guardPath, planEntry := range plan.GuardPoints {
		if _, existsInState := state.GuardPoints[guardPath]; existsInState {
			continue // already exists — handle in Phase 2
		}

		p := planEntry.GuardPointParams
		key := batchKey{
			GPType:                         p.GPType.ValueString(),
			PolicyID:                       p.PolicyID.ValueString(),
			IsAutomountEnabled:             p.IsAutomountEnabled.ValueBool(),
			IsCIFSEnabled:                  p.IsCIFSEnabled.ValueBool(),
			IsEarlyAccessEnabled:           p.IsEarlyAccessEnabled.ValueBool(),
			IsDeviceIDTCapable:             p.IsDeviceIDTCapable.ValueBool(),
			IsMFAEnabled:                   p.IsMFAEnabled.ValueBool(),
			PreserveSparseRegions:          p.PreserveSparseRegions.ValueBool(),
			NWShareCredentialsID:           p.NWShareCredentialsID.ValueString(),
			DiskName:                       p.DiskName.ValueString(),
			DiskgroupName:                  p.DiskgroupName.ValueString(),
			IsGuardEnabled:                 p.IsGuardEnabled.ValueBool(),
			IsDataClassificationEnabled:    p.IsDataClassificationEnabled.ValueBool(),
			IsDataLineageEnabled:           p.IsDataLineageEnabled.ValueBool(),
			IsIntelligentProtectionEnabled: p.IsIntelligentProtectionEnabled.ValueBool(),
		}
		if _, exists := batchMap[key]; !exists {
			batchMap[key] = &batchEntry{params: p}
			batchOrder = append(batchOrder, key)
		}
		batchMap[key].guardPaths = append(batchMap[key].guardPaths, guardPath)
		newPaths[guardPath] = true
	}

	pathToNewID := make(map[string]string)

	for _, key := range batchOrder {
		entry := batchMap[key]
		p := entry.params

		paramsPayload := buildParamsPayload(p)
		payload := CTEClientGuardPointJSON{
			GuardPaths:       entry.guardPaths,
			GuardPointParams: &paramsPayload,
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Create-in-Update", err.Error())
			return
		}

		createID := uuid.New().String()
		response, err := r.client.PostDataV2(
			ctx,
			createID,
			common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints",
			payloadJSON,
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error creating new Guardpoint during Update for client "+clientID,
				err.Error(),
			)
			return
		}

		// Parse IDs from the API response JSON by matching guard_path, not position.
		gpSize := int(gjson.Get(response, "guardpoints.#").Int())
		var createdIDs []string
		for i := 0; i < gpSize; i++ {
			returnedPath := gjson.Get(response, fmt.Sprintf("guardpoints.%d.guardpoint.guard_path", i)).String()
			returnedID := gjson.Get(response, fmt.Sprintf("guardpoints.%d.guardpoint.id", i)).String()
			if returnedPath != "" && returnedID != "" {
				pathToNewID[returnedPath] = returnedID
				createdIDs = append(createdIDs, returnedID)
			}
		}

		// PR review follow-up: same create-time-inert behavior as in Create() above --
		// explicitly disable this batch's newly created GuardPoints via the
		// dedicated endpoint whenever the plan requested guard_enabled = false.
		if !p.IsGuardEnabled.ValueBool() {
			if err := setGuardEnabled(ctx, r.client, common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints/enable", createdIDs, false); err != nil {
				resp.Diagnostics.AddError(
					"Error disabling newly created Guardpoint(s) during Update for client "+clientID,
					err.Error(),
				)
				return
			}
		}
	}

	// ---------------------------------------------------------------
	// PHASE 2 — UPDATE existing guardpoints
	// ---------------------------------------------------------------
	var allIDs []string

	for guardPath, planEntry := range plan.GuardPoints {
		var gpID string

		if newPaths[guardPath] {
			// Newly created in Phase 1 — params already sent, just record ID.
			gpID = pathToNewID[guardPath]
		} else {
			// Existing — carry state ID forward and send an update.
			stateEntry := state.GuardPoints[guardPath]
			gpID = stateEntry.ID.ValueString()

			// ---------------------------------------------------------------
			// IMMUTABLE FIELD CHECK — policy_id and guard_point_type cannot change
			// ---------------------------------------------------------------

			statePolicyID := stateEntry.GuardPointParams.PolicyID.ValueString()
			planPolicyID := planEntry.GuardPointParams.PolicyID.ValueString()
			if statePolicyID != planPolicyID {
				resp.Diagnostics.AddError(
					"Cannot change policy_id for an existing GuardPoint",
					fmt.Sprintf(
						"guard_path %q has policy_id %q in state but %q in plan. "+
							"policy_id is immutable once a GuardPoint is created. "+
							"To change it, remove this guard_path and re-add it with the new policy_id.",
						guardPath, statePolicyID, planPolicyID,
					),
				)
				return
			}

			stateGPType := stateEntry.GuardPointParams.GPType.ValueString()
			planGPType := planEntry.GuardPointParams.GPType.ValueString()
			if stateGPType != planGPType {
				resp.Diagnostics.AddError(
					"Cannot change guard_point_type for an existing GuardPoint",
					fmt.Sprintf(
						"guard_path %q has guard_point_type %q in state but %q in plan. "+
							"guard_point_type is immutable once a GuardPoint is created. "+
							"To change it, remove this guard_path and re-add it with the new guard_point_type.",
						guardPath, stateGPType, planGPType,
					),
				)
				return
			}

			// ---------------------------------------------------------------
			// DEDICATED-ENDPOINT FIELDS — early_access and preserve_sparse_regions
			// (true->false only) silently no-op via the generic PATCH below, so
			// send them through CM's dedicated sub-endpoints instead. Same
			// treatment as resource_cte_clientgroup_guardpoints.go.
			// ---------------------------------------------------------------
			stateEarlyAccess := stateEntry.GuardPointParams.IsEarlyAccessEnabled.ValueBool()
			planEarlyAccess := planEntry.GuardPointParams.IsEarlyAccessEnabled.ValueBool()
			if stateEarlyAccess != planEarlyAccess {
				earlyAccessPayloadJSON, err := json.Marshal(CTEGuardPointEarlyAccessJSON{EarlyAccess: planEarlyAccess})
				if err != nil {
					resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Early Access Update", err.Error())
					return
				}
				_, err = r.client.UpdateData(
					ctx,
					"",
					common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints/"+gpID+"/early-access",
					earlyAccessPayloadJSON,
					"",
				)
				if err != nil {
					resp.Diagnostics.AddError(
						"Error updating early_access for Guardpoint id "+gpID+" for client id "+clientID,
						err.Error(),
					)
					return
				}
			}

			// true->false is applied in place via the dedicated endpoint.
			// false->true for an existing entry is blocked at plan time by
			// BoolRequiresReplaceOnFalseToTrueUnlessNewMapEntry (CM can never
			// re-enable preserve_sparse_regions on an existing GuardPoint), so
			// this branch should only ever see a true->false transition.
			statePreserveSparse := stateEntry.GuardPointParams.PreserveSparseRegions.ValueBool()
			planPreserveSparse := planEntry.GuardPointParams.PreserveSparseRegions.ValueBool()
			if statePreserveSparse && !planPreserveSparse {
				preserveSparsePayloadJSON, err := json.Marshal(CTEGuardPointPreserveSparseRegionsOffJSON{PreserveSparseRegions: false})
				if err != nil {
					resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Preserve Sparse Regions Update", err.Error())
					return
				}
				_, err = r.client.UpdateData(
					ctx,
					"",
					common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints/"+gpID+"/preserve-sparse-regions-off",
					preserveSparsePayloadJSON,
					"",
				)
				if err != nil {
					resp.Diagnostics.AddError(
						"Error updating preserve_sparse_regions for Guardpoint id "+gpID+" for client id "+clientID,
						err.Error(),
					)
					return
				}
			}

			// ---------------------------------------------------------------
			// DEDICATED-ENDPOINT FIELD — guard_enabled (PR review follow-up). Like
			// early_access/preserve_sparse_regions above, the generic PATCH
			// below silently no-ops guard_enabled (confirmed live), so send a
			// genuine change through the dedicated enable/disable endpoint
			// instead, on both true->false and false->true transitions.
			// ---------------------------------------------------------------
			stateGuardEnabled := stateEntry.GuardPointParams.IsGuardEnabled.ValueBool()
			planGuardEnabled := planEntry.GuardPointParams.IsGuardEnabled.ValueBool()
			if stateGuardEnabled != planGuardEnabled {
				if err := setGuardEnabled(ctx, r.client, common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints/enable", []string{gpID}, planGuardEnabled); err != nil {
					resp.Diagnostics.AddError(
						"Error updating guard_enabled for Guardpoint id "+gpID+" for client id "+clientID,
						err.Error(),
					)
					return
				}
			}

			var payload UpdateCTEGuardPointJSON

			// The generic PATCH payload never included mfa_enabled here, so a
			// change to it silently never reached CM even though the field
			// exists in the schema and IS sent by the sibling
			// resource_cte_clientgroup_guardpoints.go's Update().
			//
			// Deliberately sent only when it actually changes (state vs plan),
			// NOT whenever it is merely non-null like the sibling clientgroup
			// file does: confirmed live that CM's /clients/ PATCH endpoint
			// rejects the request outright if mfa_enabled is present at all
			// on a CTE Client that lacks MFA capability ("mfa_enabled cannot
			// passed in GuardPoint as it is not supported on CTE Client"),
			// even when the value is unchanged (e.g. false -> false). Since
			// mfa_enabled is Computed+Default now, the planned value is never
			// null, so matching the clientgroup file's "if not null" pattern
			// here would resend mfa_enabled on every Update() call for every
			// existing entry -- breaking Update() entirely for any
			// MFA-incapable client even when the actual config change is to
			// an unrelated field. Only sending it on a genuine change avoids
			// that regression while still fixing the original bug.
			stateMFAEnabled := stateEntry.GuardPointParams.IsMFAEnabled.ValueBool()
			planMFAEnabled := planEntry.GuardPointParams.IsMFAEnabled.ValueBool()
			if stateMFAEnabled != planMFAEnabled {
				v := planMFAEnabled
				payload.IsMFAEnabled = &v
			}
			if planEntry.GuardPointParams.NWShareCredentialsID.ValueString() != "" {
				payload.NWShareCredentialsID = planEntry.GuardPointParams.NWShareCredentialsID.ValueString()
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Update", err.Error())
				return
			}

			_, err = r.client.UpdateData(
				ctx,
				gpID,
				common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints",
				payloadJSON,
				"",
			)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error updating Guardpoint id "+gpID+" for client id "+clientID,
					err.Error(),
				)
				return
			}

			r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_client_guardpoints.go -> Update][" + gpID + "]")
		}

		// Write the resolved ID back into the plan map entry.
		entry := plan.GuardPoints[guardPath]
		entry.ID = types.StringValue(gpID)
		plan.GuardPoints[guardPath] = entry

		allIDs = append(allIDs, gpID)
	}

	sort.Strings(allIDs)
	plan.ID = types.StringValue(strings.Join(allIDs, ","))
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func (r *resourceCTEClientGP) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEClientGuardPointTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var idList []string
	for _, entry := range state.GuardPoints {
		idList = append(idList, entry.ID.ValueString())
	}

	payload := CTEClientGuardPointUnguardJSON{
		GuardPointIdList: idList,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_client_guardpoints.go -> Delete/Unguard]")
		resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Delete/Unguard", err.Error())
		return
	}

	output, err := r.client.UpdateData(
		ctx,
		"",
		common.URL_CTE_CLIENT+"/"+state.CTEClientID.ValueString()+"/guardpoints/unguard",
		payloadJSON,
		"",
	)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_client_guardpoints.go -> Delete/Unguard][" + state.ID.ValueString() + "][" + output + "]")
	if err != nil {
		if !handleDeleteNotFound(err, "CTE Client Guardpoint "+state.ID.ValueString(), &resp.Diagnostics) {
			resp.Diagnostics.AddError(
				"Error Deleting/Unguarding CipherTrust CTE Client Guardpoint",
				"Could not delete/unguard CTE Client Guardpoint, unexpected error: "+err.Error(),
			)
			return
		}
	}

	resp.State.RemoveResource(ctx)
}

// ---------------------------------------------------------------------------
// Configure
// ---------------------------------------------------------------------------

func (d *resourceCTEClientGP) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCTEClientGP) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_cte_client_gp.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_cte_client_gp.go -> ImportState][" + id + "]")
	resource.ImportStatePassthroughID(ctx, path.Root("client_id"), req, resp)
}
