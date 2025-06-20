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
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCCKMOCIAcl{}
	_ resource.ResourceWithConfigure   = &resourceCCKMOCIAcl{}
	_ resource.ResourceWithImportState = &resourceCCKMOCIAcl{}
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

The "view" or "viewhyokkey" permissions must be included with key or "hyok key" actions respectively.`

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
		Description: "Use this resource to create and manage OCI vault access control lists (ACLs) in CipherTrust Manager.\n\n" +
			"### Import an Existing OCI ACL\n\n" +
			"To import an existing ACL, first define a resource with\n" +
			"required values matching the existing ACLS's values then run the terraform import command specifying\n" +
			"the CipherTrust Manager vault's resource ID and the user ID or group name separated by two semi-colons.\n\n" +
			"For example: `terraform import ciphertrust_oci_acl.imported_user_acl fd466e89-dc81-4d8d-bc3f-208b5f8e78a0:user::local|2f94d5b4-8563-464a-b32b-19aa50878073` or " +
			"`terraform import ciphertrust_oci_acl.imported_group_acl fd466e89-dc81-4d8d-bc3f-208b5f8e78a0:group::CCKM Users`.",
		Attributes: map[string]schema.Attribute{
			"actions": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: ociACLTable,
			},
			"group": schema.StringAttribute{
				Optional:    true,
				Description: "The CipherTrust Manager group the ACL applies to. Specify either \"user_id\" or \"group\".",
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The CipherTrust Manager vault resource ID concatenated with either the user ID or the group name separated by a semi-colon.",
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

func (r *resourceCCKMOCIAcl) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_acls.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_acls.go -> Create]["+id+"]")

	var plan models.VaultAclTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vaultID := plan.VaultID.ValueString()

	var actions []string
	resp.Diagnostics.Append(plan.Actions.ElementsAs(ctx, &actions, false)...)
	if resp.Diagnostics.HasError() {
		tflog.Debug(ctx, fmt.Sprintf("Error converting ACL actions: %v", resp.Diagnostics.Errors()))
		return
	}
	resourceID := acls.EncodeContainerAclID(vaultID, plan.UserID.ValueString(), plan.Group.ValueString())

	var response string
	if len(actions) != 0 {
		acl := acls.GetPermittedActionsPayloadJSON(ctx, resourceID, actions, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if acl != nil {
			response = r.applyAcls(ctx, id, vaultID, acl, &resp.Diagnostics, false)
			if resp.Diagnostics.HasError() {
				return
			}
			tflog.Info(ctx, fmt.Sprintf("Create response: %s", response))
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

func (r *resourceCCKMOCIAcl) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_acls.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_acls.go -> Read]["+id+"]")

	var state models.VaultAclTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resourceID := state.ID.ValueString()
	vaultID := state.VaultID.ValueString()

	response, err := r.client.GetById(ctx, id, vaultID, common.URL_OCI+"/vaults")
	if err != nil {
		msg := "Error reading OCI vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	}

	_, aclType, userIDOrGroup, err := acls.DecodeContainerAclID(resourceID)
	if err != nil {
		msg := "Error reading ACL list, invalid resource ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	for _, aclJSON := range gjson.Get(response, "acls").Array() {
		group := gjson.Get(aclJSON.String(), "group").String()
		userID := gjson.Get(aclJSON.String(), "user_id").String()
		if aclType == "group" && group == userIDOrGroup || aclType == "user" && userID == userIDOrGroup {
			response = aclJSON.String()
			r.setOCIAclState(ctx, resourceID, response, &state, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
			resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
			break
		}
	}
}

func (r *resourceCCKMOCIAcl) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *resourceCCKMOCIAcl) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_acls.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_acls.go -> Update]["+id+"]")

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

	response, err := r.client.GetById(ctx, id, vaultID, common.URL_OCI+"/vaults")
	if err != nil {
		msg := "Error reading OCI vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID, "id": resourceID})
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
		tflog.Debug(ctx, fmt.Sprintf("Error converting ACL actions: %v", resp.Diagnostics.Errors()))
		return
	}

	acl := acls.GetUnPermittedActionsPayloadJSON(ctx, resourceID, aclsJSON, planActions, &resp.Diagnostics)
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
		acl = acls.GetPermittedActionsPayloadJSON(ctx, resourceID, planActions, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if acl != nil {
			response = r.applyAcls(ctx, id, vaultID, acl, &resp.Diagnostics, false)
			if resp.Diagnostics.HasError() {
				return
			}
			tflog.Info(ctx, fmt.Sprintf("Update response: %s", response))
		}
	}

	r.setOCIAclState(ctx, resourceID, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating OCI ACL, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"id": resourceID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceCCKMOCIAcl) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_acls.go -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_acls.go -> Delete]["+id+"]")

	var state models.VaultAclTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resourceID := state.ID.ValueString()
	vaultID := state.VaultID.ValueString()

	response, err := r.client.GetById(ctx, id, vaultID, common.URL_OCI+"/vaults")
	if err != nil {
		msg := "Error reading OCI vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID, "id": resourceID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	var aclsJSON string
	if gjson.Get(response, "acls").Exists() {
		aclsJSON = gjson.Get(response, "acls").String()
	}
	payloadJSON := acls.GetUnPermittedActionsPayloadJSON(ctx, resourceID, aclsJSON, []string{}, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if payloadJSON != nil {
		response = r.applyAcls(ctx, id, vaultID, payloadJSON, &resp.Diagnostics, true)
		if resp.Diagnostics.HasError() {
			return
		}
		tflog.Info(ctx, fmt.Sprintf("Delete response: %s", response))
	}
}

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
	response, err := r.client.PostDataV2(ctx, id, common.URL_OCI+"/vaults/"+vaultID+"/update-acls", payloadJSON)
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
	return response
}

func (r *resourceCCKMOCIAcl) setOCIAclState(ctx context.Context, resourceID string, responseJSON string, state *models.VaultAclTFSDK, diags *diag.Diagnostics) {
	acls.SetAclCommonState(ctx, resourceID, responseJSON, &state.AclTFSDK, diags)
}
