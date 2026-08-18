package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
)

var (
	_ resource.Resource                = &resourceCTEClientGroupGP{}
	_ resource.ResourceWithConfigure   = &resourceCTEClientGroupGP{}
	_ resource.ResourceWithImportState = &resourceCTEClientGroupGP{}
)

func NewResourceCTEClientGroupGP() resource.Resource {
	return &resourceCTEClientGroupGP{}
}

type resourceCTEClientGroupGP struct {
	client *common.Client
}

func (r *resourceCTEClientGroupGP) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_clientgroup_guardpoint"
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

func (r *resourceCTEClientGroupGP) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A GuardPoint specifies the list of folders that contains paths to be protected." +
			" Access to files and encryption of files under the GuardPoint is controlled by security policies." +
			" GuardPoints created on a client group are applied to all clients in the group." +
			" Terraform Destroy will unguard the paths.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Comma-separated list of GuardPoint IDs managed by this resource.",
			},
			"client_group_id": schema.StringAttribute{
				Required:    true,
				Description: "CTE Client Group ID.",
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
									Required:    true,
									Description: "(Immutable) Type of the GuardPoint.",
									Validators: []validator.String{
										stringvalidator.OneOf([]string{
											"directory_auto", "directory_manual",
											"rawdevice_manual", "rawdevice_auto",
											"cloudstorage_auto", "cloudstorage_manual",
											"ransomware_protection",
										}...),
									},
									PlanModifiers: []planmodifier.String{
										// TFIN-521: guard_point_type carries the immutable-unless-
										// new-map-entry modifier, not plain RequiresReplace() or
										// RequiresReplaceUnlessNewMapEntry(): CM's PATCH returns
										// 200 OK but silently leaves guard_point_type unchanged, so
										// a destroy+recreate needlessly tears down and rebuilds the
										// guardpoint (briefly unguarding the path) for a change CM
										// never actually supports at all. ImmutableStringUnlessNewMapEntry
										// hard-blocks the change at plan time instead (no destroy, no
										// unguarding), while still allowing a brand-new guard_path to
										// be created in place with any guard_point_type. Same class
										// as TFIN-632 (policy_id on this same resource) and TFIN-642
										// (policy_type on ciphertrust_cte_policy).
										modifiers.ImmutableStringUnlessNewMapEntry(),
									},
								},
								"policy_id": schema.StringAttribute{
									Required:    true,
									Description: "ID of the policy applied with this GuardPoint. policy_id is immutable once a GuardPoint is created: changing it for an EXISTING guard_path forces a whole-resource replace. Adding a brand-new guard_path with any policy_id does not force a replace -- it is created in place by Update().",
									PlanModifiers: []planmodifier.String{
										// TFIN-632: policy_id was Required with no PlanModifiers at
										// all, so a change was planned as a normal in-place update
										// and only rejected at apply time by Update()'s manual
										// AddError check. RequiresReplaceUnlessNewMapEntry (not plain
										// RequiresReplace(), which would reintroduce TFIN-634's
										// destructive-replace-on-add bug) surfaces the immutability
										// at plan time via -/+ replace for a genuine change to an
										// EXISTING entry, while a brand-new guard_path is still
										// created in place.
										modifiers.RequiresReplaceUnlessNewMapEntry(),
									},
								},
								"automount_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether automount is enabled with the GuardPoint. Changing this value for an EXISTING guard_path forces the whole resource to be replaced, since CM silently no-ops an update to this field via PATCH.",
									PlanModifiers: []planmodifier.Bool{
										// TFIN-633: CM silently no-ops an update to this field via
										// PATCH -- apply reported success but the field never
										// actually changed on CM, and state permanently diverged
										// with no way to detect it. Force a replace instead so the
										// change actually takes effect (via destroy+recreate).
										modifiers.BoolRequiresReplaceUnlessNewMapEntry(),
									},
								},
								"cifs_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether to enable CIFS. Changing this value for an EXISTING guard_path forces the whole resource to be replaced, since CM silently no-ops an update to this field via PATCH.",
									PlanModifiers: []planmodifier.Bool{
										// TFIN-633: see automount_enabled above.
										modifiers.BoolRequiresReplaceUnlessNewMapEntry(),
									},
								},
								"data_classification_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether data classification is enabled. Changing this value for an EXISTING guard_path forces the whole resource to be replaced, since CM silently no-ops an update to this field via PATCH.",
									PlanModifiers: []planmodifier.Bool{
										// TFIN-633: see automount_enabled above. Also needs the
										// TFIN-628 batchKey fix (this field is complementary, not
										// redundant): the batchKey fix protects it at Create/Update
										// batch-create time, this plan modifier protects it against
										// no-op updates on an already-existing entry.
										modifiers.BoolRequiresReplaceUnlessNewMapEntry(),
									},
								},
								"data_lineage_enabled": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether data lineage is enabled. Changing this value for an EXISTING guard_path forces the whole resource to be replaced, since CM silently no-ops an update to this field via PATCH.",
									PlanModifiers: []planmodifier.Bool{
										// TFIN-633: see data_classification_enabled above (same
										// batchKey + plan-modifier complementary relationship).
										modifiers.BoolRequiresReplaceUnlessNewMapEntry(),
									},
								},
								"disk_name": schema.StringAttribute{
									Optional:    true,
									Description: "Name of the disk for Oracle ASM disk group. Changing this value for an EXISTING guard_path forces the whole resource to be replaced, since CM silently no-ops an update to this field via PATCH.",
									PlanModifiers: []planmodifier.String{
										// TFIN-633: see automount_enabled above (String variant).
										modifiers.RequiresReplaceUnlessNewMapEntry(),
									},
								},
								"diskgroup_name": schema.StringAttribute{
									Optional:    true,
									Description: "Name of the disk group for Oracle ASM. Changing this value for an EXISTING guard_path forces the whole resource to be replaced, since CM silently no-ops an update to this field via PATCH.",
									PlanModifiers: []planmodifier.String{
										// TFIN-633: see automount_enabled above (String variant).
										modifiers.RequiresReplaceUnlessNewMapEntry(),
									},
								},
								"early_access": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether secure start is turned on. Changing this value for an EXISTING guard_path is applied in place via a dedicated CM endpoint -- it does not force a replace.",
									// TFIN-633's original finding (CM silently no-ops this field via
									// the generic PATCH) does not apply here: CM has a dedicated
									// early-access endpoint that supports both true->false and
									// false->true in place for an existing GuardPoint, so no plan
									// modifier is needed. Update() calls that dedicated endpoint
									// directly on a genuine change instead of relying on the generic
									// PATCH.
								},
								"intelligent_protection": schema.BoolAttribute{
									Optional:    true,
									Description: "Flag to enable intelligent protection. Changing this value for an EXISTING guard_path forces the whole resource to be replaced, since CM silently no-ops an update to this field via PATCH.",
									PlanModifiers: []planmodifier.Bool{
										// TFIN-633: see data_classification_enabled above (same
										// batchKey + plan-modifier complementary relationship).
										modifiers.BoolRequiresReplaceUnlessNewMapEntry(),
									},
								},
								"is_idt_capable_device": schema.BoolAttribute{
									Optional:    true,
									Description: "Whether the device is IDT capable. Changing this value for an EXISTING guard_path forces the whole resource to be replaced, since CM silently no-ops an update to this field via PATCH.",
									PlanModifiers: []planmodifier.Bool{
										// TFIN-633: see automount_enabled above.
										modifiers.BoolRequiresReplaceUnlessNewMapEntry(),
									},
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
										// TFIN-633 (refined): CM's generic PATCH silently no-ops this
										// field, but CM has a dedicated preserve-sparse-regions-off
										// endpoint that handles true->false in place. false->true is
										// genuinely impossible via any API call once a GuardPoint has
										// been created with (or later turned to) false -- destroy and
										// recreate is the only way to get a "true" GuardPoint back.
										// BoolRequiresReplaceOnFalseToTrueUnlessNewMapEntry forces
										// replace only for that direction on an existing entry; Update()
										// calls the dedicated endpoint for true->false.
										modifiers.BoolRequiresReplaceOnFalseToTrueUnlessNewMapEntry(),
									},
								},
								"guard_enabled": schema.BoolAttribute{
									Optional:    true,
									Computed:    true,
									Default:     booldefault.StaticBool(true),
									Description: "Whether the GuardPoint is enabled. Changing this value for an EXISTING guard_path is applied in place via a dedicated CM endpoint -- it does not force a replace.",
									// PR review follow-up: see resource_cte_client_guardpoints.go's
									// guard_enabled for the full rationale -- same treatment
									// applied here for consistency between the two resources.
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

func (r *resourceCTEClientGroupGP) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cte_clientgroup_guardpoints.go -> Create][" + id + "]")

	var plan CTEClientGroupGuardPointTFSDK
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
		// TFIN-628/TFIN-544: these 4 fields were missing from the comparison
		// key. Two guard points differing ONLY in one of these fields used
		// to hash to the same batchKey and collapse into a single batched
		// POST /guardpoints call, so only one guard point's requested value
		// for that field actually reached CM ("first writer wins") while the
		// other silently got whichever value happened to be stored first for
		// the shared key.
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
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_clientgroup_guardpoints.go -> Create][" + id + "]")
			resp.Diagnostics.AddError("Invalid data input: CTE ClientGroup Guardpoint Creation", err.Error())
			return
		}

		response, err := r.client.PostDataV2(
			ctx,
			id,
			common.URL_CTE_CLIENT_GROUP+"/"+plan.CTEClientGroupID.ValueString()+"/guardpoints",
			payloadJSON,
		)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_clientgroup_guardpoints.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Error creating CTE ClientGroup Guardpoint on CipherTrust Manager: ",
				"Could not create CTE ClientGroup Guardpoint, unexpected error: "+err.Error(),
			)
			return
		}

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
			if err := setGuardEnabled(ctx, r.client, common.URL_CTE_CLIENT_GROUP+"/"+plan.CTEClientGroupID.ValueString()+"/guardpoints/enable/", createdIDs, false); err != nil {
				r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_clientgroup_guardpoints.go -> Create/GuardEnabled][" + id + "]")
				resp.Diagnostics.AddError(
					"Error disabling newly created Guardpoint(s) for client group "+plan.CTEClientGroupID.ValueString(),
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

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_clientgroup_guardpoints.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

func (r *resourceCTEClientGroupGP) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEClientGroupGuardPointTFSDK
	id := uuid.New().String()

	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cte_clientgroup_guardpoints.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	clientGroupID := state.CTEClientGroupID.ValueString()

	response, err := r.client.GetById(ctx, id, "", common.URL_CTE_CLIENT_GROUP+"/"+clientGroupID+"/guardpoints")
	if handleReadNotFound(ctx, err, "CTE ClientGroup Guardpoints (client group "+clientGroupID+")", &resp.Diagnostics) {
		return
	}

	if response == "" {
		resp.Diagnostics.AddError(
			"CTE ClientGroup Guardpoints (client group "+clientGroupID+") not found",
			"Guardpoints for CTE ClientGroup "+clientGroupID+" returned an empty response from CipherTrust Manager during refresh, indicating the parent client group or its guardpoints may have been removed out-of-band. Keeping this resource in Terraform state rather than removing it, since this may be a transient issue or a change that should be reconciled deliberately.",
		)
		return
	}

	var envelope struct {
		Resources []CTEClientGuardPointListJSON `json:"resources"`
	}
	if err := json.Unmarshal([]byte(response), &envelope); err != nil {
		resp.Diagnostics.AddError(
			"Error parsing Guardpoints response for ClientGroup id "+clientGroupID,
			err.Error(),
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
				IsMFAEnabled:   types.BoolValue(gp.MFAEnabled),
				IsGuardEnabled: types.BoolValue(gp.GuardEnabled),
				PolicyID:       types.StringValue(gp.PolicyID),
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

	// If every guard_path this resource was tracking in state has disappeared
	// from CM (out-of-band deletion via the /unguard action, since direct
	// DELETE is not supported), the resource no longer exists. Remove it from
	// state so Terraform plans a clean "+create" on the next apply instead of
	// an "~ update in-place" that the framework's plan-consistency check will
	// reject once Update() recreates the guardpoint with a new id.
	if len(state.GuardPoints) > 0 {
		anyTrackedPathStillExists := false
		for guardPath := range state.GuardPoints {
			if _, found := newGuardPoints[guardPath]; found {
				anyTrackedPathStillExists = true
				break
			}
		}
		if !anyTrackedPathStillExists {
			resp.Diagnostics.AddError(
				"CTE ClientGroup Guardpoints (client group "+clientGroupID+") not found",
				"All guard_points previously tracked for CTE ClientGroup "+clientGroupID+" no longer exist on CipherTrust Manager, indicating they were removed out-of-band (e.g. via the /unguard action). Keeping this resource in Terraform state rather than removing it, since this may be a transient issue or a change that should be reconciled deliberately.",
			)
			return
		}
	}

	state.GuardPoints = newGuardPoints
	sort.Strings(allIDs)
	state.ID = types.StringValue(strings.Join(allIDs, ","))

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_clientgroup_guardpoints.go -> Read][" + id + "]")
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (r *resourceCTEClientGroupGP) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state CTEClientGroupGuardPointTFSDK

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

	//immutable field handling for client group id
	if state.CTEClientGroupID.ValueString() != plan.CTEClientGroupID.ValueString() {
		resp.Diagnostics.AddError("Cannot change client_id", "client_id is an immutable field")
		return
	}

	clientGroupID := plan.CTEClientGroupID.ValueString()

	// ---------------------------------------------------------------
	// PHASE 0 — UNGUARD guardpoints whose guard_path was removed from plan.
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
			resp.Diagnostics.AddError("Invalid data input: CTE ClientGroup Guardpoint Unguard during Update", err.Error())
			return
		}

		_, err = r.client.UpdateData(
			ctx,
			"",
			common.URL_CTE_CLIENT_GROUP+"/"+clientGroupID+"/guardpoints/unguard",
			unguardPayloadJSON,
			"",
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error unguarding removed Guardpoints for client group "+clientGroupID,
				err.Error(),
			)
			return
		}

		r.client.Log.Trace("[resource_cte_clientgroup_guardpoints.go -> Update/Unguard] unguarded IDs: " + strings.Join(removedIDs, ","))
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
		// TFIN-628/TFIN-544: these 4 fields were missing from the comparison
		// key. Two guard points differing ONLY in one of these fields used
		// to hash to the same batchKey and collapse into a single batched
		// POST /guardpoints call, so only one guard point's requested value
		// for that field actually reached CM ("first writer wins") while the
		// other silently got whichever value happened to be stored first for
		// the shared key.
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
	newPaths := make(map[string]bool)

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
			resp.Diagnostics.AddError("Invalid data input: CTE ClientGroup Guardpoint Create-in-Update", err.Error())
			return
		}

		createID := uuid.New().String()
		response, err := r.client.PostDataV2(
			ctx,
			createID,
			common.URL_CTE_CLIENT_GROUP+"/"+clientGroupID+"/guardpoints",
			payloadJSON,
		)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error creating new Guardpoint during Update for client group "+clientGroupID,
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
			if err := setGuardEnabled(ctx, r.client, common.URL_CTE_CLIENT_GROUP+"/"+clientGroupID+"/guardpoints/enable/", createdIDs, false); err != nil {
				resp.Diagnostics.AddError(
					"Error disabling newly created Guardpoint(s) during Update for client group "+clientGroupID,
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
			// send them through CM's dedicated sub-endpoints instead.
			// ---------------------------------------------------------------
			stateEarlyAccess := stateEntry.GuardPointParams.IsEarlyAccessEnabled.ValueBool()
			planEarlyAccess := planEntry.GuardPointParams.IsEarlyAccessEnabled.ValueBool()
			if stateEarlyAccess != planEarlyAccess {
				earlyAccessPayloadJSON, err := json.Marshal(CTEGuardPointEarlyAccessJSON{EarlyAccess: planEarlyAccess})
				if err != nil {
					resp.Diagnostics.AddError("Invalid data input: CTE ClientGroup Guardpoint Early Access Update", err.Error())
					return
				}
				_, err = r.client.UpdateData(
					ctx,
					"",
					common.URL_CTE_CLIENT_GROUP+"/"+clientGroupID+"/guardpoints/"+gpID+"/early-access",
					earlyAccessPayloadJSON,
					"",
				)
				if err != nil {
					resp.Diagnostics.AddError(
						"Error updating early_access for Guardpoint id "+gpID+" for client group "+clientGroupID,
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
					resp.Diagnostics.AddError("Invalid data input: CTE ClientGroup Guardpoint Preserve Sparse Regions Update", err.Error())
					return
				}
				_, err = r.client.UpdateData(
					ctx,
					"",
					common.URL_CTE_CLIENT_GROUP+"/"+clientGroupID+"/guardpoints/"+gpID+"/preserve-sparse-regions-off",
					preserveSparsePayloadJSON,
					"",
				)
				if err != nil {
					resp.Diagnostics.AddError(
						"Error updating preserve_sparse_regions for Guardpoint id "+gpID+" for client group "+clientGroupID,
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
				if err := setGuardEnabled(ctx, r.client, common.URL_CTE_CLIENT_GROUP+"/"+clientGroupID+"/guardpoints/enable/", []string{gpID}, planGuardEnabled); err != nil {
					resp.Diagnostics.AddError(
						"Error updating guard_enabled for Guardpoint id "+gpID+" for client group "+clientGroupID,
						err.Error(),
					)
					return
				}
			}

			var payload UpdateCTEGuardPointJSON
			if !planEntry.GuardPointParams.IsMFAEnabled.IsNull() {
				v := planEntry.GuardPointParams.IsMFAEnabled.ValueBool()
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
				common.URL_CTE_CLIENT_GROUP+"/"+clientGroupID+"/guardpoints",
				payloadJSON,
				"",
			)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error updating Guardpoint id "+gpID+" for client group "+clientGroupID,
					err.Error(),
				)
				return
			}

			r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_clientgroup_guardpoints.go -> Update][" + gpID + "]")
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

func (r *resourceCTEClientGroupGP) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEClientGroupGuardPointTFSDK
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
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cte_clientgroup_guardpoints.go -> Delete/Unguard]")
		resp.Diagnostics.AddError("Invalid data input: CTE Client Guardpoint Delete/Unguard", err.Error())
		return
	}

	output, err := r.client.UpdateData(
		ctx,
		"",
		common.URL_CTE_CLIENT_GROUP+"/"+state.CTEClientGroupID.ValueString()+"/guardpoints/unguard",
		payloadJSON,
		"",
	)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cte_clientgroup_guardpoints.go -> Delete/Unguard][" + state.ID.ValueString() + "][" + output + "]")
	if err != nil {
		if !handleDeleteNotFound(err, "CTE Client Group Guardpoint "+state.ID.ValueString(), &resp.Diagnostics) {
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

func (r *resourceCTEClientGroupGP) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = client
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildParamsPayload converts the TFSDK params struct to the JSON payload
// struct used by the API. Extracted to avoid duplication between Create and
// the Phase 1 create-in-Update path.
func buildParamsPayload(p CTEClientGuardPointParamsTFSDK) CTEClientGuardPointParamsJSON {
	var out CTEClientGuardPointParamsJSON
	out.GPType = p.GPType.ValueString()
	out.PolicyID = p.PolicyID.ValueString()
	out.IsAutomountEnabled = p.IsAutomountEnabled.ValueBool()
	out.IsCIFSEnabled = p.IsCIFSEnabled.ValueBool()
	out.IsDataClassificationEnabled = p.IsDataClassificationEnabled.ValueBool()
	out.IsDataLineageEnabled = p.IsDataLineageEnabled.ValueBool()
	out.IsEarlyAccessEnabled = p.IsEarlyAccessEnabled.ValueBool()
	out.IsIntelligentProtectionEnabled = p.IsIntelligentProtectionEnabled.ValueBool()
	out.IsDeviceIDTCapable = p.IsDeviceIDTCapable.ValueBool()
	out.IsMFAEnabled = p.IsMFAEnabled.ValueBool()
	out.PreserveSparseRegions = p.PreserveSparseRegions.ValueBool()
	// PR review follow-up: populated for completeness, but confirmed live that CM's
	// Create endpoint ignores it -- a follow-up call to the dedicated
	// enable/disable endpoint is required whenever guard_enabled = false
	// (see the Create()/Update() Phase 1 callers of buildParamsPayload).
	out.IsGuardEnabled = p.IsGuardEnabled.ValueBool()
	if p.DiskName.ValueString() != "" {
		out.DiskName = p.DiskName.ValueString()
	}
	if p.DiskgroupName.ValueString() != "" {
		out.DiskgroupName = p.DiskgroupName.ValueString()
	}
	if p.NWShareCredentialsID.ValueString() != "" {
		out.NWShareCredentialsID = p.NWShareCredentialsID.ValueString()
	}
	return out
}

// setGuardEnabled calls the dedicated batch PATCH .../guardpoints/enable(/)
// endpoint to actually enable/disable the given GuardPoint IDs. PR review
// follow-up: confirmed live against CM that guard_enabled is inert both on Create
// (a GuardPoint created with guard_enabled = false still comes up true) and
// via the generic PATCH .../guardpoints/{id} used for other fields -- this
// dedicated endpoint is the only one that reliably applies the change,
// verified in both directions (true->false and false->true) via a
// follow-up GET on the GuardPoint. Shared by both resource_cte_client_guardpoints.go
// and resource_cte_clientgroup_guardpoints.go, same as buildParamsPayload.
func setGuardEnabled(ctx context.Context, client *common.Client, enableEndpoint string, guardPointIDs []string, enabled bool) error {
	if len(guardPointIDs) == 0 {
		return nil
	}
	payload := CTEGuardPointEnableJSON{
		GuardPointIdList: guardPointIDs,
		IsGuardEnabled:   enabled,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = client.UpdateData(ctx, "", enableEndpoint, payloadJSON, "")
	return err
}

func (r *resourceCTEClientGroupGP) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_cte_client_group_gp.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_cte_client_group_gp.go -> ImportState][" + id + "]")
	resource.ImportStatePassthroughID(ctx, path.Root("client_group_id"), req, resp)
}
