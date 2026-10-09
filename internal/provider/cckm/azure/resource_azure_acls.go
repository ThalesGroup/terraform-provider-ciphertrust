package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
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
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCCKMAzureAcl{}
	_ resource.ResourceWithConfigure   = &resourceCCKMAzureAcl{}
	_ resource.ResourceWithImportState = &resourceCCKMAzureAcl{}
)

func NewResourceCCKMAzureAcl() resource.Resource {
	return &resourceCCKMAzureAcl{}
}

type resourceCCKMAzureAcl struct {
	client *common.Client
}

func (r *resourceCCKMAzureAcl) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_acl"
}

const azureACLTable = `The following table lists the accepted values:

| APIs                             |  Actions                 | Description |
| -------------------------------- |  ----------------------- | --------------------------------------------------- |
| List / Get (keys)                |  view                    | Permission to view vaults and their keys. |
| Create                           |  keycreate               | Permission to create an Azure native key. |
| Upload                           |  keyupload               | Permission to upload a CipherTrust Manager key to Azure. |
| Update                           |  keyupdate               | Permission to update keys, for example, editing attributes, enabling/disabling keys and editing tags. |
| Soft Delete                      |  keydelete               | Permission to soft delete an Azure key from the vault. |
| Purge                            |  keypurge                | Permission to permanently delete a soft-deleted Azure key. |
| Recover                          |  keyrecover              | Permission to recover a soft-deleted Azure key. |
| Restore                          |  keyrestore              | Permission to restore a backed up key to a vault. |
| Synchronize / Cancel             |  keysynchronize          | Permission to synchronize Azure keys and to cancel a synchronization job. |
| Delete Backup                    |  deletebackup            | Permission to delete an Azure key and its versions from CCKM. |
| | | |
| Create Secret                    |  secretcreate            | Permission to create an Azure secret. |
| Recover Secret                   |  secretrecover           | Permission to recover a soft-deleted Azure secret. |
| Purge Secret                     |  secretpurge             | Permission to permanently delete an Azure secret. |
| Soft Delete Secret               |  secretdelete            | Permission to soft delete an Azure secret from the vault. |
| Synchronize Secret / Cancel      |  secretsynchronize       | Permission to synchronize Azure secrets and to cancel a synchronization job. |
| Restore Secret                   |  secretrestore           | Permission to restore a backed up secret to a vault. |
| Update Secret                    |  secretupdate            | Permission to update secret attributes and tags. |
| Delete Secret Backup             |  secretdeletebackup      | Permission to delete an Azure secret and its versions from CCKM. |
| Get / List Secrets               |  secretview              | Permission to view secrets of a vault. |
| | | |
| Create Certificate               |  certificatecreate       | Permission to create an Azure certificate. |
| Recover Certificate              |  certificaterecover      | Permission to recover a soft-deleted Azure certificate. |
| Purge Certificate                |  certificatepurge        | Permission to permanently delete an Azure certificate. |
| Soft Delete Certificate          |  certificatedelete       | Permission to soft delete an Azure certificate from the vault. |
| Synchronize Certificate / Cancel |  certificatesynchronize  | Permission to synchronize Azure certificates and to cancel a synchronization job. |
| Restore Certificate              |  certificaterestore      | Permission to restore a backed up certificate to a vault. |
| Update Certificate               |  certificateupdate       | Permission to update certificate attributes and tags. |
| Delete Certificate Backup        |  certificatedeletebackup | Permission to delete an Azure certificate and its versions from CCKM. |
| Get / List Certificates          |  certificateview         | Permission to view certificates of a vault. |
| Upload Certificate               |  certificateupload       | Permission to upload a CipherTrust Manager certificate to Azure. |
| | | |
| Create Report                    |  reportcreate            | Permission to create a report. |
| Delete Report                    |  reportdelete            | Permission to delete a report. |
| Download Report                  |  reportdownload          | Permission to download a report. |
| View Report                      |  reportview              | Permission to view report content. |
| | | |
| Create (key template)            |  keycreatewithtemplate   | Permission to create an Azure key using a key template. |
| Upload (key template)            |  uploadkeywithtemplate   | Permission to upload an Azure key using a key template. |
| | | |
| Create Key Template              |  createkeytemplate       | Permission to create an Azure key template. |
| List / Get Key Templates         |  viewkeytemplate         | Permission to view Azure key templates and get the details of a key template. |
| Update Key Template              |  updatekeytemplate       | Permission to update an Azure key template. |
| Delete Key Template              |  deletekeytemplate       | Permission to delete an Azure key template. |

The 'view' permission must be included with the 'key' actions, 'secretview' with the 'secret' actions and 'certificateview' with the 'certificate' actions. 'viewkeytemplate' must be included with the key template actions ('view' as well for 'keycreatewithtemplate' and 'uploadkeywithtemplate').

To remove a user or group from the vault ACL entirely, delete the resource.`

func (r *resourceCCKMAzureAcl) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCCKMAzureAcl) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage Azure vault access control lists (ACLs) in CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			"actions": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "" + azureACLTable,
				Validators:          []validator.Set{setvalidator.SizeAtLeast(1)},
			},
			"group": schema.StringAttribute{
				Optional:      true,
				Description:   "(Immutable) The CipherTrust Manager group the ACL applies to. Specify either \"user_id\" or \"group\".",
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
			},
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The CipherTrust Manager vault resource ID concatenated with either the user ID or the group name separated by a semi-colon.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"user_id": schema.StringAttribute{
				Optional:      true,
				Description:   "(Immutable) ID of the CipherTrust Manager user the ACL applies to. For example: \"local|57a191ec-8644-4e2f-aaa9-59ca2ba0dbf9\". Specify either \"user_id\" or \"group\".",
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
			},
			"vault_id": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) The CipherTrust Manager Azure vault resource ID in which to set the ACL.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
			},
		},
	}
}

// Create builds a composite resource ID from the vault ID and user/group identity, then grants the
// specified actions via applyAcls. Once the resource ID is set, subsequent state failures are
// demoted to warnings only.
func (r *resourceCCKMAzureAcl) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_acls.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_acls.go -> Create][" + id + "]")

	var plan models.AzureVaultAclTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vaultID := plan.VaultID.ValueString()

	var actions []string
	resp.Diagnostics.Append(plan.Actions.ElementsAs(ctx, &actions, false)...)
	if resp.Diagnostics.HasError() {
		r.client.Log.Error(fmt.Sprintf("Error converting ACL actions: %v", resp.Diagnostics.Errors()))
		return
	}
	resourceID := acls.EncodeContainerAclID(vaultID, plan.UserID.ValueString(), plan.Group.ValueString())

	var response string
	if len(actions) != 0 {
		acl := acls.GetPermittedAcl(r.client, resourceID, actions, &resp.Diagnostics)
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
	r.setAzureAclState(resourceID, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read retrieves the vault JSON and extracts the current acls array to refresh state. If the
// specific user/group ACL entry is absent from the vault ACL list, an error is returned so the
// user can remove the resource from their Terraform config.
func (r *resourceCCKMAzureAcl) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_acls.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_acls.go -> Read][" + id + "]")

	var state models.AzureVaultAclTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resourceID := state.ID.ValueString()
	vaultID, _, _, err := acls.DecodeContainerAclID(resourceID)
	if err != nil {
		msg := "Error reading ACL list, invalid resource ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	state.VaultID = types.StringValue(vaultID)
	response := getAzureVault(ctx, id, r.client, vaultID, "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !acls.AclExistsInResponse(response, resourceID) {
		msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "Azure vault ACL")
		details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID, "id": resourceID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.setAzureAclState(resourceID, response, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update first revokes any actions currently granted that are absent from the new plan
// (via GetUnPermittedAcl + applyAcls), then grants the new plan actions (via GetPermittedAcl + applyAcls).
func (r *resourceCCKMAzureAcl) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_acls.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_acls.go -> Update][" + id + "]")

	var plan models.AzureVaultAclTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state models.AzureVaultAclTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resourceID := state.ID.ValueString()
	vaultID := state.VaultID.ValueString()
	plan.ID = state.ID

	response := getAzureVault(ctx, id, r.client, vaultID, "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !acls.AclExistsInResponse(response, resourceID) {
		msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "Azure vault ACL")
		details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID, "id": resourceID})
		r.client.Log.Error(details)
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
		r.client.Log.Error(fmt.Sprintf("Error converting ACL actions: %v", resp.Diagnostics.Errors()))
		return
	}

	acl := acls.GetUnPermittedAcl(r.client, resourceID, aclsJSON, planActions, &resp.Diagnostics)
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
		acl = acls.GetPermittedAcl(r.client, resourceID, planActions, &resp.Diagnostics)
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

	r.setAzureAclState(resourceID, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete revokes all currently-granted actions by calling GetUnPermittedAcl with an empty new-actions
// slice, then applying the revocation via applyAcls.
func (r *resourceCCKMAzureAcl) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_acls.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_acls.go -> Delete][" + id + "]")

	var state models.AzureVaultAclTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resourceID := state.ID.ValueString()
	vaultID := state.VaultID.ValueString()

	response := getAzureVault(ctx, id, r.client, vaultID, "deleting", &resp.Diagnostics)
	if resp.Diagnostics.HasError() || response == "" {
		return
	}
	if !acls.AclExistsInResponse(response, resourceID) {
		msg := "Azure vault ACL was not found, it will be removed from state."
		details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID, "id": resourceID})
		r.client.Log.Warn(details)
		resp.Diagnostics.AddWarning(details, "")
		return
	}
	var aclsJSON string
	if gjson.Get(response, "acls").Exists() {
		aclsJSON = gjson.Get(response, "acls").String()
	}
	acl := acls.GetUnPermittedAcl(r.client, resourceID, aclsJSON, []string{}, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if acl != nil {
		_ = r.applyAcls(ctx, id, vaultID, acl, &resp.Diagnostics, true)
		if resp.Diagnostics.HasError() {
			return
		}
	}
}

// ImportState imports an existing Azure ACL into Terraform state. The import ID must be the composite
// ACL resource ID in the form {vault_id}::{user|group}::{identity}.
func (r *resourceCCKMAzureAcl) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_acls.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_acls.go -> ImportState][" + id + "]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// applyAcls is used by Create, Update, and Delete. It acquires a per-vault mutex before posting to
// POST /azure/vaults/{id}/update-acls. The update is internal to CipherTrust Manager so no 409 retry
// is needed. The ignoreNotFoundErrors flag is only set to true by Delete; when set, an
// NCERRResourceNotFound response is silently ignored (the vault was already deleted externally).
func (r *resourceCCKMAzureAcl) applyAcls(ctx context.Context, id string, vaultID string, acl *acls.ContainerAclJSON, diags *diag.Diagnostics, ignoreNotFoundErrors bool) string {
	mutexKey := fmt.Sprintf("azure-acls-%s", vaultID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	payload := acls.BaseAclsJSON{
		ContainerAcls: []acls.ContainerAclJSON{*acl},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating ACL list, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID, "userID": acl.UserID, "group": acl.Group, "actions": strings.Join(acl.Actions, ",")})
		r.client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AZURE+"/vaults/"+vaultID+"/update-acls", payloadJSON)
	if err != nil {
		if ignoreNotFoundErrors && strings.Contains(err.Error(), "NCERRResourceNotFound") {
			return ""
		}
		msg := "Error updating Azure ACL list."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID, "userID": acl.UserID, "group": acl.Group, "actions": strings.Join(acl.Actions, ",")})
		r.client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// setAzureAclState is used only by this resource. It delegates to acls.SetAclCommonState to locate the
// matching ACL entry within the vault JSON response and populate the state struct.
func (r *resourceCCKMAzureAcl) setAzureAclState(resourceID string, responseJSON string, state *models.AzureVaultAclTFSDK, diags *diag.Diagnostics) {
	acls.SetAclCommonState(r.client, resourceID, responseJSON, &state.AclTFSDK, diags)
}
