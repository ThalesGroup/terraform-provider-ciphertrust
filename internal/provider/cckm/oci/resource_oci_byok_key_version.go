package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCCKMOCIByokVersion{}
	_ resource.ResourceWithConfigure   = &resourceCCKMOCIByokVersion{}
	_ resource.ResourceWithImportState = &resourceCCKMOCIByokVersion{}
)

func NewResourceCCKMOCIByokVersion() resource.Resource {
	return &resourceCCKMOCIByokVersion{}
}

type resourceCCKMOCIByokVersion struct {
	client *common.Client
}

func (r *resourceCCKMOCIByokVersion) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_byok_key_version"
}

func (r *resourceCCKMOCIByokVersion) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCCKMOCIByokVersion) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage OCI BYOK key versions in CipherTrust Manager.\n" +
			"First create a source key in one of the supported source key tiers then specify the source key tier and ID of the key.\n\n" +
			"### Import an Existing BYOK Key Version\n\n" +
			"To import an existing BYOK key version, first define a resource with\n" +
			"required values matching the existing version's values then run the terraform import command specifying\n" +
			"the key's CipherTrust Manager resource ID and the version's CipherTrust Manager resource ID separated by a colon on the command line.\n\n" +
			"For example: `terraform import ciphertrust_oci_byok_version.imported_key_version d5f40cfe-eaa0-4657-9862-ba3982a0e2be:013b3896-4a83-4592-8c81-b6acb6a6ef38`.",
		Attributes: map[string]schema.Attribute{
			"account": schema.StringAttribute{
				Computed:    true,
				Description: "The account which owns this resource.",
			},
			"cckm_key_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager Key ID.",
			},
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager cloud name.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the application was created",
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The key's CipherTrust Manager resource ID.",
			},
			"key_material_origin": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager origin of the key version's material.",
			},
			"oci_key_version_params": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "OCI key attributes.",
				Attributes: map[string]schema.Attribute{
					"compartment_id": schema.StringAttribute{
						Computed:    true,
						Description: "The compartment's OCID.",
					},
					"is_primary": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether the key belongs to a primary vault or a replica vault.",
					},
					"key_id": schema.StringAttribute{
						Computed:    true,
						Description: "The key's OCID.",
					},
					"lifecycle_state": schema.StringAttribute{
						Computed:    true,
						Description: "The key version's current lifecycle state.",
					},
					"origin": schema.StringAttribute{
						Computed:    true,
						Description: "Origin of the version;s key material.",
					},
					"public_key": schema.StringAttribute{
						Computed:    true,
						Description: "Version's public key.",
					},
					"replication_id": schema.StringAttribute{
						Computed:    true,
						Description: "The replication ID associated with a key version operation.",
					},
					"restored_from_key_version_id": schema.StringAttribute{
						Computed:    true,
						Description: "Key version OCID from which this key version was restored.",
					},
					"time_created": schema.StringAttribute{
						Computed:    true,
						Description: "The time the key version was created.",
					},
					"time_of_deletion": schema.StringAttribute{
						Computed:    true,
						Description: "The time when the key version will be deleted.",
					},
					"vault_id": schema.StringAttribute{
						Computed:    true,
						Description: "OCI Vault OCID.",
					},
					"version_id": schema.StringAttribute{
						Computed:    true,
						Description: "OCI version ID",
					},
				},
			},
			"refreshed_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the key was refreshed.",
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "(Updatable) Waiting period after the key is destroyed before the key is deleted. Only relevant when the resource is destroyed. Default is " + strconv.Itoa(scheduleForDeletionDays) + ".",
				Default:     int64default.StaticInt64(scheduleForDeletionDays),
				Validators: []validator.Int64{
					int64validator.AtLeast(scheduleForDeletionDays),
				},
			},
			"source_key_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the key that will be uploaded from a key source to OCI.",
			},
			"source_key_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the key that will be uploaded from the key source to OCI.",
			},
			"source_key_tier": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("local"),
				Description: "Key source from where the key will be uploaded. The default is 'local'. The only option is 'local'.",
				Validators:  []validator.String{stringvalidator.OneOf([]string{"local"}...)},
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the application was updated.",
			},
			"uri": schema.StringAttribute{
				Description: "CipherTrust Manager's unique identifier for the resource.",
				Computed:    true,
			},
		},
	}
}

func (r *resourceCCKMOCIByokVersion) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_byok_version.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_byok_version.go -> Create]["+id+"]")

	mutexKey := fmt.Sprintf("ocikeyversion-%s", id)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	var plan models.BYOKKeyVersionTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyID := plan.CCKMKeyID.ValueString()
	payload := models.AddKeyVersionPayloadJSON{
		IsNative:      false,
		SourceKeyID:   plan.SourceKeyID.ValueString(),
		SourceKeyTier: plan.SourceKeyTier.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error uploading key to OCI, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_OCI+"/keys/"+keyID+"/versions", payloadJSON)
	if err != nil {
		msg := "Error adding key version to OCI."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	versionID := gjson.Get(response, "id").String()
	plan.ID = types.StringValue(versionID)

	// No errors now

	var waitDiags diag.Diagnostics
	waitForKeyVersionState(ctx, id, r.client, keyID, versionID, keyStateEnabled, &waitDiags)
	if waitDiags.HasError() {
		for _, d := range waitDiags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}

	response, err = r.client.GetById(ctx, id, versionID, common.URL_OCI+"/keys/"+keyID+"/versions")
	if err != nil {
		msg := "Error reading OCI key version."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "version_id": versionID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		return
	}

	var setStateDiags diag.Diagnostics
	setBYOOKKeyVersionState(ctx, response, &plan, &setStateDiags)
	if setStateDiags.HasError() {
		for _, d := range setStateDiags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	tflog.Trace(ctx, "[resource_oci_byok_keyversion.go -> Create][response:"+response)
}

func (r *resourceCCKMOCIByokVersion) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_byok_version.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_byok_version.go -> Read]["+id+"]")

	var state models.BYOKKeyVersionTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	versionID := state.ID.ValueString()

	keyID := state.CCKMKeyID.ValueString()
	response, err := r.client.GetById(ctx, id, versionID, common.URL_OCI+"/keys/"+keyID+"/versions")
	if err != nil {
		msg := "Error reading OCI key version."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "version_id": versionID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	setBYOOKKeyVersionState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	tflog.Trace(ctx, "[resource_oci_byok_keyversion.go -> Read][response:"+response)
}

func (r *resourceCCKMOCIByokVersion) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_byok_version.go -> Import]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_byok_version.go -> Import]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)

	ids := strings.Split(req.ID, ":")
	if len(ids) != 2 {
		msg := "Error importing key version, please pass in keyID:versionID on command line as the version's id. For example: f9fc3532-6a75-423d-9c04-5c802384acd5:5c2da105-99cf-4c6a-9f7c-2199783cc759"
		tflog.Error(ctx, msg)
		resp.Diagnostics.AddError(msg, "")
		return
	}
	keyID := ids[0]
	versionID := ids[1]

	var state models.BYOKKeyVersionTFSDK
	resp.Diagnostics.Append(resp.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.ID = types.StringValue(versionID)
	state.CCKMKeyID = types.StringValue(keyID)
	response, err := r.client.GetById(ctx, id, versionID, common.URL_OCI+"/keys/"+keyID+"/versions")
	if err != nil {
		msg := "Error reading OCI key version."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "version_id": versionID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	state.ScheduleForDeletionDays = types.Int64Value(7)
	setBYOOKKeyVersionState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	tflog.Trace(ctx, "[resource_oci_byok_keyversion.go -> Import][response:"+response)
}

func (r *resourceCCKMOCIByokVersion) Update(ctx context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_byok_version.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_byok_version.go -> Update]["+id+"]")
}

func (r *resourceCCKMOCIByokVersion) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_byok_version.go -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_byok_version.go -> Delete]["+id+"]")
	var state models.BYOKKeyVersionTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.CCKMKeyID.ValueString()
	versionID := state.ID.ValueString()
	days := state.ScheduleForDeletionDays.ValueInt64()
	deleteKeyVersion(ctx, id, r.client, keyID, versionID, days, &resp.Diagnostics)
}

func setBYOOKKeyVersionState(ctx context.Context, response string, state *models.BYOKKeyVersionTFSDK, diags *diag.Diagnostics) {
	setCommonKeyVersionState(ctx, response, &state.KeyVersionTFSDK, diags)
	state.SourceKeyID = types.StringValue(gjson.Get(response, "source_key_identifier").String())
	state.SourceKeyName = types.StringValue(gjson.Get(response, "source_key_name").String())
	state.SourceKeyTier = types.StringValue(gjson.Get(response, "source_key_tier").String())
}
