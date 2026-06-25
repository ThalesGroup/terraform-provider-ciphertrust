package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCCKMOCIAcl{}
	_ resource.ResourceWithConfigure   = &resourceCCKMOCIAcl{}
	_ resource.ResourceWithImportState = &resourceCCKMOCIAcl{}
	_ resource.ResourceWithModifyPlan  = &resourceCCKMOCIAcl{}
)

func NewResourceCCKMOCIAcl() resource.Resource {
	return &resourceCCKMOCIAcl{}
}

type resourceCCKMOCIAcl struct {
	client *common.Client
}

func (r *resourceCCKMOCIAcl) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_acl"
}

const ociACLTable = `The following table lists the accepted values:

| APIs                            |  Actions               | Description |
| -----------------------------   |  --------------------- | --------------------------------------------------- |
| List                            |  view                  | Permission to view vaults and their keys. |
| Create                          |  keycreate             | Permission to create a OCI native keys. |
| Upload                          |  keyupload             | Permission to upload the CipherTrust Manager keys to OCI. |
| Schedule Deletion               |  keydelete             | Permission for schedule deletion of the key. |
| Cancel scheduled deletion       |  keycanceldelete       | Permission to cancel deletion of the keys. |
| Restore                         |  keyrestore            | Permission to restore a backed up keys to a vault. |
| Update (Edit key)               |  keyupdate             | Permission to update keys, for example, editing properties, enabling/disabling keys, and editing tags. |
| Delete Backup                   |  deletebackup          | Permission to delete backups of OCI keys from the CCKM. |
| Rotate to Native Key            |  keyrotatetonative     | Permission to rotate the keys on OCI vaults natively. |
| Rotate to BYOK Key              |  keyrotatetobyok       | Permission to rotate the keys on OCI vaults BYOK. |
| Synchronize                     |  keysynchronize        | Permission to synchronize OCI keys. |
| Cancel                          |  keysynchronize        | Permission to cancel a synchronization jobs. |
| Remove                          |  keyremove             | Permission to remove OCI keys with their versions and backups from the CCKM. |
| Create Report                   |  reportcreate          | Permission to create report. |
| Delete Report                   |  reportdelete          | Permission to delete report. |
| Download Report                 |  reportdownload        | Permission to download report. |
| View Report                     |  reportview            | Permission to view report content. |
| List     (HYOK Vaults and Keys) |  viewhyokkey           | Permission to view OCI HYOK vaults and their keys. |
| Create   (HYOK Key)             |  hyokkeycreate         | Permission to create an OCI HYOK key. |
| Update   (HYOK Key)             |  hyokkeyupdate         | Permission to update an OCI HYOK key. |
| Block                           |  hyokkeyblockunblock   | Permission to block all the proxy operations on the OCI HYOK key. |
| Unblock                         |  hyokkeyblockunblock   | Permission to unblock all the proxy operations on the OCI HYOK key. |
| Delete  (HYOK Key)              |  hyokkeydelete         | Permission to delete an OCI HYOK key (applicable only to unlinked key). |
| Rotate  (HYOK Key)              |  hyokkeyrotate         | Permission to rotate a HYOK key in CM. |

The 'view' or 'viewhyokkey' permissions must be included with 'key' or 'hyok key' actions respectively.

To remove a user or group from the vault ACL entirely, delete the resource.`

func (r *resourceCCKMOCIAcl) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCCKMOCIAcl) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage OCI vault access control lists (ACLs) in CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			"actions": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "(Updatable) " + ociACLTable,
				Validators:          []validator.Set{setvalidator.SizeAtLeast(1)},
			},
			"group": schema.StringAttribute{
				Optional:    true,
				Description: "The CipherTrust Manager group the ACL applies to. Specify either \"user_id\" or \"group\".",
			},
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The CipherTrust Manager vault resource ID concatenated with either the user ID or the group name separated by a semi-colon.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"user_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the CipherTrust Manager user the ACL applies to. For example: \"user::local|57a191ec-8644-4e2f-aaa9-59ca2ba0dbf9\" .Specify either \"user_id\" or \"group\".",
			},
			"vault_id": schema.StringAttribute{
				Required:    true,
				Description: "The CipherTrust Manager OCI vault resource ID in which to set the ACL",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
		},
	}
}

// Create builds a composite resource ID from the vault ID and user/group identity, then grants the
// specified actions via applyAcls. If actions is empty, no ACL call is made and the resource ID is
// still committed to state. Once the resource ID is set, subsequent setOCIAclState failures are
// demoted to warnings only.
func (r *resourceCCKMOCIAcl) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_acls.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_acls.go -> Create]["+id+"]")

	var plan models.VaultAclTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vaultID := plan.VaultID.ValueString()

	var actions []string
	resp.Diagnostics.Append(plan.Actions.ElementsAs(ctx, &actions, false)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, fmt.Sprintf("Error converting ACL actions: %v", resp.Diagnostics.Errors()))
		return
	}
	resourceID := acls.EncodeContainerAclID(vaultID, plan.UserID.ValueString(), plan.Group.ValueString())

	var response string
	if len(actions) != 0 {
		acl := acls.GetPermittedAcl(ctx, resourceID, actions, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if acl != nil {
			response = r.applyAcls(ctx, id, vaultID, acl, &resp.Diagnostics, false)
			if resp.Diagnostics.HasError() {
				return
			}
		}
	}

	plan.ID = types.StringValue(resourceID)

	// No errors after this

	var diags diag.Diagnostics
	r.setOCIAclState(ctx, resourceID, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read retrieves the vault JSON via getOciVault and extracts the current acls array to
// refresh state. If the specific user/group ACL entry is absent from the vault ACL list, an error
// is returned so the user can remove the resource from their Terraform config.
func (r *resourceCCKMOCIAcl) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_acls.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_acls.go -> Read]["+id+"]")

	var state models.VaultAclTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resourceID := state.ID.ValueString()
	vaultID, _, _, err := acls.DecodeContainerAclID(resourceID)
	if err != nil {
		msg := "Error reading ACL list, invalid resource ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	state.VaultID = types.StringValue(vaultID)
	response := getOciVault(ctx, id, r.client, vaultID, "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !acls.AclExistsInResponse(response, resourceID) {
		msg := "OCI vault ACL not found. If it no longer exists, remove it from your Terraform config."
		details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID, "id": resourceID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.setOCIAclState(ctx, resourceID, response, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update first revokes any actions currently granted that are absent from the new plan
// (via GetUnPermittedAcl + applyAcls), then grants the new plan actions (via GetPermittedAcl + applyAcls).
func (r *resourceCCKMOCIAcl) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_acls.go -> Update]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_acls.go -> Update]["+id+"]")

	var plan models.VaultAclTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state models.VaultAclTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resourceID := state.ID.ValueString()
	vaultID := state.VaultID.ValueString()
	plan.ID = state.ID

	response := getOciVault(ctx, id, r.client, vaultID, "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !acls.AclExistsInResponse(response, resourceID) {
		msg := "OCI vault ACL was not found, cannot update."
		details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID, "id": resourceID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	var aclsJSON string
	if gjson.Get(response, "acls").Exists() {
		aclsJSON = gjson.Get(response, "acls").String()
	}
	var planActions []string
	resp.Diagnostics.Append(plan.Actions.ElementsAs(ctx, &planActions, false)...)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, fmt.Sprintf("Error converting ACL actions: %v", resp.Diagnostics.Errors()))
		return
	}

	acl := acls.GetUnPermittedAcl(ctx, resourceID, aclsJSON, planActions, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if acl != nil {
		response = r.applyAcls(ctx, id, vaultID, acl, &resp.Diagnostics, false)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if len(planActions) != 0 {
		acl = acls.GetPermittedAcl(ctx, resourceID, planActions, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if acl != nil {
			response = r.applyAcls(ctx, id, vaultID, acl, &resp.Diagnostics, false)
			if resp.Diagnostics.HasError() {
				return
			}
		}
	}

	r.setOCIAclState(ctx, resourceID, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete revokes all currently-granted actions by calling GetUnPermittedAcl with an empty new-actions
// slice, then applying the revocation via applyAcls.
func (r *resourceCCKMOCIAcl) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_acls.go -> Delete]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_acls.go -> Delete]["+id+"]")

	var state models.VaultAclTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resourceID := state.ID.ValueString()
	vaultID := state.VaultID.ValueString()

	response := getOciVault(ctx, id, r.client, vaultID, "deleting", &resp.Diagnostics)
	if resp.Diagnostics.HasError() || response == "" {
		return
	}
	if !acls.AclExistsInResponse(response, resourceID) {
		msg := "OCI vault ACL was not found, it will be removed from state."
		details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID, "id": resourceID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		return
	}
	var aclsJSON string
	if gjson.Get(response, "acls").Exists() {
		aclsJSON = gjson.Get(response, "acls").String()
	}
	acl := acls.GetUnPermittedAcl(ctx, resourceID, aclsJSON, []string{}, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if acl != nil {
		response = r.applyAcls(ctx, id, vaultID, acl, &resp.Diagnostics, true)
		if resp.Diagnostics.HasError() {
			return
		}
	}
}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource,
// preventing silent in-place updates to fields that cannot be modified after creation.
// group, user_id, and vault_id together form the composite resource ID and cannot be changed.
func (r *resourceCCKMOCIAcl) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy operations.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state models.VaultAclTFSDK

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var changed []string

	// Guard against false positives when group is not set in config (null in plan)
	// while state holds an empty string returned by the API (e.g. when user_id was used instead).
	if !plan.Group.IsNull() && !plan.Group.IsUnknown() && plan.Group != state.Group {
		changed = append(changed, "group")
	}
	// Guard against false positives when user_id is not set in config (null in plan)
	// while state holds an empty string returned by the API (e.g. when group was used instead).
	if !plan.UserID.IsNull() && !plan.UserID.IsUnknown() && plan.UserID != state.UserID {
		changed = append(changed, "user_id")
	}

	if plan.VaultID != state.VaultID {
		changed = append(changed, "vault_id")
	}

	if len(changed) > 0 {
		resp.Diagnostics.AddError(
			"Immutable attribute change detected",
			fmt.Sprintf(
				"The following attributes cannot be modified after creation: %s. "+
					"Delete and recreate the resource to apply these changes.",
				strings.Join(changed, ", "),
			),
		)
	}
}

// ImportState imports an existing OCI ACL into Terraform state. The import ID must be the composite
// ACL resource ID in the form {vault_id}::{user|group}::{identity}.
func (r *resourceCCKMOCIAcl) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_acls.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_acls.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// applyAcls is used by Create, Update, and Delete. It acquires a per-vault mutex before posting to
// POST /oci/vaults/{id}/update-acls. The ignoreNotFoundErrors flag is only set to true by Delete;
// when set, an NCERRResourceNotFound response from the update-acls endpoint is silently ignored
// (the vault was already deleted externally).
func (r *resourceCCKMOCIAcl) applyAcls(ctx context.Context, id string, vaultID string, acl *acls.ContainerAclJSON, diags *diag.Diagnostics, ignoreNotFoundErrors bool) string {
	mutexKey := fmt.Sprintf("oci-acls-%s", vaultID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)
	payload := acls.BaseAclsJSON{
		ContainerAcls: []acls.ContainerAclJSON{*acl},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating ACL list, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID, "userID": acl.UserID, "group": acl.Group, "actions": strings.Join(acl.Actions, ",")})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	response, err := ociPostDataV2WithRetry(ctx, r.client, id, common.URL_OCI+"/vaults/"+vaultID+"/update-acls", payloadJSON)
	if err != nil {
		if ignoreNotFoundErrors && strings.Contains(err.Error(), "NCERRResourceNotFound") {
			return ""
		} else {
			msg := "Error updating OCI ACL list."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID, "userID": acl.UserID, "group": acl.Group, "actions": strings.Join(acl.Actions, ",")})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return ""
		}
	}
	tflog.Debug(ctx, "[resource_oci_acls.go -> applyAcls][response:"+redactOCIResponse(response)+"]")
	return response
}

// setOCIAclState is used only by this resource. It delegates to acls.SetAclCommonState to locate the
// matching ACL entry within the vault JSON response and populate the state struct.
func (r *resourceCCKMOCIAcl) setOCIAclState(ctx context.Context, resourceID string, responseJSON string, state *models.VaultAclTFSDK, diags *diag.Diagnostics) {
	acls.SetAclCommonState(ctx, resourceID, responseJSON, &state.AclTFSDK, diags)
}
