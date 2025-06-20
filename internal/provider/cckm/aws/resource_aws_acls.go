package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
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
	_ resource.Resource                = &resourceCCKMAWSAcl{}
	_ resource.ResourceWithConfigure   = &resourceCCKMAWSAcl{}
	_ resource.ResourceWithImportState = &resourceCCKMAWSAcl{}
)

func NewResourceCCKMAWSAcl() resource.Resource {
	return &resourceCCKMAWSAcl{}
}

type resourceCCKMAWSAcl struct {
	client *common.Client
}

func (r *resourceCCKMAWSAcl) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_acl"
}

const awsACLTable = `The following table lists the accepted values:

|APIs                             |  Actions Required             | Description |
|-------------------------------  |  ---------------------------- | ---------------------------------------------------|
|Create                           |  keycreate                    | Permission to create an AWS key. |
|Import                           |  keymaterialimport            | Permission to import the key on the AWS KMS. |
|Delete key material              |  keymaterialdelete            | Permission to delete the imported key material from AWS KMS. |
|Rotate                           |  keyrotate                    | Permission to rotate the key on the AWS KMS. |
|Schedule Deletion                |  keydelete                    | Permission for schedule deletion of the key. |
|Cancel delete                    |  keycanceldelete              | Permission to cancel deletion of the key. |
|Synchronize                      |  keysynchronize               | Permission to synchronize AWS keys. |
|Cancel                           |  keysynchronize               | Permission to cancel a synchronization job. |
|Update key policy                |  keyupdate                    | Permission to update the AWS key policy. |
|Update key description           |  keyupdate                    | Permission to update the AWS key description. |
|Enable key                       |  keyupdate                    | Permission to enable the AWS key. |
|Disable key                      |  keyupdate                    | Permission to disable the AWS key. |
|Add tags                         |  keyupdate                    | Permission to add tags to the AWS key. |
|Remove tags                      |  keyupdate                    | Permission to remove tags from the AWS key. |
|Add alias                        |  keyupdate                    | Permission to add an alias to the AWS key. |
|Delete alias                     |  keyupdate                    | Permission to deletes alias from the AWS key. |
|Enable key rotation              |  keyupdate                    | Permission to enable automatic key rotation of the AWS key. |
|Disable key rotation             |  keyupdate                    | Permission to disables automatic key rotation of the AWS key. |
|Upload                           |  keyupload                    | Permission to upload the key to the AWS KMS. |
|List                             |  viewnative                   | Permission to view kms and its native keys. |
|List                             |  viewbyok                     | Permission to view kms and its external keys. |
|Get (AWS Keys)                   |  viewnative/viewbyok          | Permission to get the details of an AWS key with the given id. |
|List AWS KMS                     |  viewnative/viewbyok          | Permission to view kms and its keys. |
|Get (AWS Kms)                    |  viewnative/viewbyok          | Permission to get the details of AWS KMS with the given id. |
|Create Report                    |  reportcreate                 | Permission to create report. |
|Delete Report                    |  reportdelete                 | Permission to delete report. |
|Download Report                  |  reportdownload               | Permission to download report. |
|View Report                      |  reportview                   | Permission to view report content. |
|List (HYOK Key)                  |  viewhyokkey                  | Permission to view AWS HYOK keys. |
|Create (HYOK Key)                |  hyokkeycreate                | Permission to create an AWS HYOK key. |
|Block/Unblock (HYOK Key)         |  hyokkeyblockunblock          | Permission to block/unblock an AWS HYOK key. |
|Delete (HYOK Key)                |  hyokkeydelete                | Permission to delete an AWS HYOK key (applicable only to unlinked key). |
|Link (HYOK Key)                  |  hyokkeylink                  | Permission to link an HYOK key in CM to HYOK key in AWS. |
|List (CloudHSM Key)              |  viewcloudhsmkey              | Permission to view AWS CloudHSM keys. |
|Create (CloudHSM Key)            |  cloudhsmkeycreate            | Permission to create an AWS CloudHSM key. |
|Delete (CloudHSM Key)            |  cloudhsmkeydelete            | Permission to delete an AWS CloudHSM key. |
|List (Custom Key Store)          |  viewkeystore                 | Permission to view Custom key stores. |
|Create (Custom Key Store)        |  keystoreadd                  | Permission to add Custom key store. |
|Update (Custom Key Store)        |  keystoreupdate               | Permission to update Custom key store properties. |
|Delete (Custom Key Store)        |  keystoredelete               | Permission to delete Custom key store. |
|Block (Custom Key Store)         |  keystoreblock                | Permission to block any operations on keys in Custom key store.                         |
|Unblock (Custom Key Store)       |  keystoreunblock              | Permission to unblock operations on keys in Custom key store. |
|Connect (Custom Key Store)       |  keystoreconnect              | Permission to connect Custom key store to AWS. |
|Disconnect (Custom Key Store)    |  keystoredisconnect           | Permission to disconnect Custom key store from AWS. |
|Link (Custom Key Store)          |  keystorelink                 | Permission to link Custom key store to AWS. |
|Bulk operation                   |  keybulkoperation             | Permission to perform bulk job operations. |

Note: It's not necessary to add any view permissions as they will be automatically added.

For backwards compatibility the deprecated "view" permission will be automatically converted to 'viewnative' and 'viewbyok' permissions.`

func (r *resourceCCKMAWSAcl) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCCKMAWSAcl) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage AWS KMS access control lists (ACLs) in CipherTrust Manager.\n\n" +
			"### Import an Existing AWS ACL\n\n" +
			"To import an existing ACL, first define a resource with\n" +
			"required values matching the existing ACLS's values (including either 'user_id' or 'group') then run the terraform\n" +
			"import command specifying the CipherTrust Manager KMS resource ID and the user ID or group name separated by two semi-colons.\n\n" +
			"For example: `terraform import ciphertrust_aws_acl.imported_user_acl fd466e89-dc81-4d8d-bc3f-208b5f8e78a0:user::local|2f94d5b4-8563-464a-b32b-19aa50878073` or " +
			"`terraform import ciphertrust_aws_acl.imported_group_acl fd466e89-dc81-4d8d-bc3f-208b5f8e78a0:group::CCKM Users`.",
		Attributes: map[string]schema.Attribute{
			"actions": schema.SetAttribute{
				Required:            true,
				ElementType:         types.StringType,
				MarkdownDescription: awsACLTable,
			},
			"kms_actions": schema.SetAttribute{
				Computed:    true,
				Description: "Actions saved in the KMS for this user or group including automatically added view ACL's.",
				ElementType: types.StringType,
			},
			"group": schema.StringAttribute{
				Optional:    true,
				Description: "The CipherTrust Manager group the ACL applies to. Specify either \"user_id\" or \"group\".",
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The CipherTrust Manager KMS resource ID concatenated with either the user ID or the group name separated by two semi-colons.",
			},
			"user_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the CipherTrust Manager user the ACL applies to. For example: \"user::local|57a191ec-8644-4e2f-aaa9-59ca2ba0dbf9\" .Specify either \"user_id\" or \"group\".",
			},
			"kms_id": schema.StringAttribute{
				Required:    true,
				Description: "The CipherTrust Manager AWS KMS resource ID in which to set the ACL",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
		},
	}
}

func (r *resourceCCKMAWSAcl) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_acls.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_acls.go -> Create]["+id+"]")

	var plan KMSAclTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	kmsID := plan.KmsID.ValueString()

	var actions []string
	resp.Diagnostics.Append(plan.Actions.ElementsAs(ctx, &actions, false)...)
	if resp.Diagnostics.HasError() {
		tflog.Debug(ctx, fmt.Sprintf("Error converting ACL actions: %v", resp.Diagnostics.Errors()))
		return
	}
	resourceID := acls.EncodeContainerAclID(kmsID, plan.UserID.ValueString(), plan.Group.ValueString())

	var response string
	if len(actions) != 0 {
		acl := acls.GetPermittedAcl(ctx, resourceID, actions, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if acl != nil {
			response = r.applyAcls(ctx, id, kmsID, acl, &resp.Diagnostics, false)
			if resp.Diagnostics.HasError() {
				return
			}
			tflog.Info(ctx, fmt.Sprintf("Create response: %s", response))
		}
	}

	plan.ID = types.StringValue(resourceID)

	// No errors after this

	var diags diag.Diagnostics
	r.setAWSAclState(ctx, resourceID, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceCCKMAWSAcl) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_acls.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_acls.go -> Read]["+id+"]")

	var state KMSAclTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resourceID := state.ID.ValueString()
	kmsID := state.KmsID.ValueString()

	response, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS+"/kms")
	if err != nil {
		msg := "Error reading AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": kmsID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	}
	r.setAWSAclState(ctx, resourceID, response, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *resourceCCKMAWSAcl) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *resourceCCKMAWSAcl) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_acls.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_acls.go -> Update]["+id+"]")

	var plan KMSAclTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state KMSAclTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resourceID := state.ID.ValueString()
	kmsID := state.KmsID.ValueString()
	plan.ID = state.ID

	response, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS+"/kms")
	if err != nil {
		msg := "Error reading AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": kmsID, "id": resourceID})
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

	acl := acls.GetUnPermittedAcl(ctx, resourceID, aclsJSON, planActions, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if acl != nil {
		response = r.applyAcls(ctx, id, kmsID, acl, &resp.Diagnostics, false)
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
			response = r.applyAcls(ctx, id, kmsID, acl, &resp.Diagnostics, false)
			if resp.Diagnostics.HasError() {
				return
			}
			tflog.Info(ctx, fmt.Sprintf("Update response: %s", response))
		}
	}
	r.setAWSAclState(ctx, resourceID, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating AWS ACL, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"id": resourceID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceCCKMAWSAcl) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_acls.go -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_acls.go -> Delete]["+id+"]")

	var state KMSAclTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resourceID := state.ID.ValueString()
	kmsID := state.KmsID.ValueString()

	response, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS+"/kms")
	if err != nil {
		msg := "Error reading AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": kmsID, "id": resourceID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
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
		response = r.applyAcls(ctx, id, kmsID, acl, &resp.Diagnostics, true)
		if resp.Diagnostics.HasError() {
			return
		}
		tflog.Info(ctx, fmt.Sprintf("Delete response: %s", response))
	}
}

func (r *resourceCCKMAWSAcl) applyAcls(ctx context.Context, id string, kmsID string, acl *acls.ContainerAclJSON, diags *diag.Diagnostics, ignoreNotFoundErrors bool) string {
	mutexKey := fmt.Sprintf("aws-acls-%s", kmsID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	payload := acls.BaseAclsJSON{
		ContainerAcls: []acls.ContainerAclJSON{*acl},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating ACL list, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID, "userID": acl.UserID, "group": acl.Group, "actions": strings.Join(acl.Actions, ",")})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS+"/kms/"+kmsID+"/update-acls", payloadJSON)
	if err != nil {
		if ignoreNotFoundErrors && strings.Contains(err.Error(), "NCERRResourceNotFound") {
			return ""
		} else {
			msg := "Error updating AWS ACL list."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID, "userID": acl.UserID, "group": acl.Group, "actions": strings.Join(acl.Actions, ",")})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return ""
		}
	}
	tflog.Trace(ctx, "[resource_aws_acls.go -> applyAcls][response:"+response)
	return response
}

func (r *resourceCCKMAWSAcl) setAWSAclState(ctx context.Context, resourceID string, responseJSON string, state *KMSAclTFSDK, diags *diag.Diagnostics) {
	inputActions := state.Actions
	acls.SetAclCommonState(ctx, resourceID, responseJSON, &state.AclTFSDK, diags)
	if len(state.Actions.Elements()) != 0 {
		state.KmsActions = state.Actions
	} else {
		var dg diag.Diagnostics
		state.KmsActions, dg = types.SetValue(types.StringType, []attr.Value{})
		if dg.HasError() {
			diags.Append(dg...)
			return
		}
	}
	state.Actions = inputActions
}
