package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCCKMOCIKey{}
	_ resource.ResourceWithConfigure   = &resourceCCKMOCIKey{}
	_ resource.ResourceWithImportState = &resourceCCKMOCIKey{}
)

func NewResourceCCKMOCIKey() resource.Resource {
	return &resourceCCKMOCIKey{}
}

type resourceCCKMOCIKey struct {
	client *common.Client
}

func (r *resourceCCKMOCIKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_key"
}

func (r *resourceCCKMOCIKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCCKMOCIKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage native OCI keys in CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			"account": schema.StringAttribute{
				Computed:    true,
				Description: "The account which owns this resource.",
			},
			"auto_rotate": schema.BoolAttribute{
				Description: "Whether the key is enabled for auto-rotation.",
				Computed:    true,
			},
			"cloud_name": schema.StringAttribute{
				Description: "CipherTrust Manager cloud name.",
				Computed:    true,
			},
			"compartment_name": schema.StringAttribute{
				Computed:    true,
				Description: "The compartment's name.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the key was created in CipherTrust Manager.",
			},
			"enable_auto_rotation": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "(Updatable) Enable the key for a scheduled rotation job.",
				Attributes: map[string]schema.Attribute{
					"job_config_id": schema.StringAttribute{
						Required:    true,
						Description: "(Updatable) CipherTrust Manager resource ID of a key rotation scheduler.",
					},
					"key_source": schema.StringAttribute{
						Required:    true,
						Description: "(Updatable) Currently, the only option is 'ciphertrust'.",
						Validators:  []validator.String{stringvalidator.OneOf([]string{"ciphertrust"}...)},
					},
				},
			},
			"enable_key": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Updatable) Enable or disable the key. Default is true.",
				Default:     booldefault.StaticBool(true),
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The keys CipherTrust Manager resource ID.",
			},
			"key_material_origin": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager origin of the key's material.",
			},
			"labels": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "A list of key:value pairs associated with the key.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "(Updatable) Name for the key.",
			},
			"oci_key_params": schema.SingleNestedAttribute{
				Required:    true,
				Description: "OCI key attributes.",
				Attributes: map[string]schema.Attribute{
					"algorithm": schema.StringAttribute{
						Required:    true,
						Description: "The algorithm used by the key's versions to encrypt or decrypt. Options are AES, RSA and ECDSA.",
						Validators:  []validator.String{stringvalidator.OneOf([]string{"AES", "RSA", "ECDSA"}...)},
					},
					"compartment_id": schema.StringAttribute{
						Required:    true,
						Description: "(Updateable) The compartment's OCID in which to create the key.",
					},
					"current_key_version": schema.StringAttribute{
						Computed:    true,
						Description: "The OCID of the key's current version.",
					},
					"curve_id": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Description: "The curve ID of the ECDSA key. Options are NIST_P256, NIST_P384 and NIST_P521.",
						Validators:  []validator.String{stringvalidator.OneOf([]string{"NIST_P256", "NIST_P384", "NIST_P521"}...)},
					},
					"defined_tags": schema.SetNestedAttribute{
						Optional:    true,
						Computed:    true,
						Description: "(Updatable) Defined tags for the key.",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"tag": schema.StringAttribute{
									Optional:    true,
									Description: "The tag's namespace as defined in OCI.",
								},
								"values": schema.MapAttribute{
									Optional:    true,
									ElementType: types.StringType,
									Description: "The key:value pairs to associate with the tag as defined in OCI.",
								},
							},
						},
					},
					"display_name": schema.StringAttribute{
						Computed:    true,
						Description: "The key's name.",
					},
					"freeform_tags": schema.MapAttribute{
						Optional:    true,
						Computed:    true,
						ElementType: types.StringType,
						Description: "(Updatable) Freeform tags for the key. Freeform tags are key:value pairs.",
					},
					"is_primary": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether the key belongs to a primary vault or a replica vault.",
					},
					"key_id": schema.StringAttribute{
						Computed:    true,
						Description: "The key's OCID.",
					},
					"length": schema.Int64Attribute{
						Required: true,
						Description: "The length of the key in bytes. Options are: " +
							"AES (16, 24, 32), RSA (256, 384, 512), ECDSA (32, 48, 66).",
					},
					"lifecycle_state": schema.StringAttribute{
						Computed:    true,
						Description: "The key's current lifecycle state.",
					},
					"protection_mode": schema.StringAttribute{
						Required:    true,
						Description: "The protection mode of the key. Options are: HSM or SOFTWARE.",
						Validators:  []validator.String{stringvalidator.OneOf([]string{"HSM", "SOFTWARE"}...)},
					},
					"replication_id": schema.StringAttribute{
						Computed:    true,
						Description: "The replication ID associated with a key operation.",
					},
					"restored_from_key_id": schema.StringAttribute{
						Computed:    true,
						Description: "The OCID of the key from which this key was restored.",
					},
					"time_created": schema.StringAttribute{
						Computed:    true,
						Description: "The time the key was created.",
					},
					"time_of_deletion": schema.StringAttribute{
						Computed:    true,
						Description: "The time when the key will be deleted.",
					},
					"vault_name": schema.StringAttribute{
						Computed:    true,
						Description: "The vault's name.",
					},
				},
			},
			"refreshed_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the key was refreshed.",
			},
			"region": schema.StringAttribute{
				Computed:    true,
				Description: "The key's region.",
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
			"tenancy": schema.StringAttribute{
				Computed:    true,
				Description: "OCI tenancy in which the key is created.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the application was updated.",
			},
			"uri": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager's unique identifier for the resource.",
			},
			"vault": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager OCI vault resource ID.",
			},
			"vault_id": schema.StringAttribute{
				Computed:    true,
				Description: "The vault's OCID.",
			},
			"version_summary": schema.ListNestedAttribute{
				Computed:    true,
				Description: "Key version summary.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"cckm_version_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager version ID.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the version was created in CipherTrust Manager.",
						},
						"source_key_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager key ID used to create the version.",
						},
						"source_key_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the key used to create the version.",
						},
						"source_key_tier": schema.StringAttribute{
							Computed:    true,
							Description: "Source of the key used to create the version.",
						},
						"version_id": schema.StringAttribute{
							Computed:    true,
							Description: "The key version's OCID",
						},
					},
				},
			},
		},
	}
}

func (r *resourceCCKMOCIKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_key.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_key.go -> Create]["+id+"]")

	var plan models.KeyTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := models.CreateKeyRequest{
		Algorithm:      plan.KeyParams.Algorithm.ValueString(),
		CompartmentID:  plan.KeyParams.CompartmentID.ValueString(),
		Curve:          plan.KeyParams.CurveID.ValueString(),
		Length:         plan.KeyParams.Length.ValueInt64(),
		Name:           plan.Name.ValueString(),
		ProtectionMode: plan.KeyParams.ProtectionMode.ValueString(),
		Vault:          plan.Vault.ValueString(),
	}
	definedTags := getDefinedTagsFromPlan(ctx, &plan.KeyParams.DefinedTags, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload.DefinedTags = definedTags
	freeformTags := getFreeformTagsFromPlan(ctx, &plan.KeyParams.FreeformTags, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload.FreeformTags = freeformTags

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating OCI key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "name": payload.Name})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_OCI+"/keys", payloadJSON)
	if err != nil {
		msg := "Error creating OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "name": payload.Name})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[resource_resource_oci_key.go -> Create][response:"+response)
	keyID := gjson.Get(response, "id").String()
	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	plan.ID = types.StringValue(keyID)

	// no errors after this as the key is created

	var waitDiags diag.Diagnostics
	waitForKeyStateChange(ctx, id, r.client, keyID, keyState, false, &waitDiags)
	if waitDiags.HasError() {
		for _, d := range waitDiags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}

	if plan.EnableAutoRotation != nil {
		var diags diag.Diagnostics
		enableSchedulerRotation(ctx, id, r.client, keyID, plan.EnableAutoRotation, &diags)
		if diags.HasError() {
			for _, d := range diags {
				resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
			}
		}
	}

	if !plan.EnableKey.ValueBool() {
		var diags diag.Diagnostics
		disableKey(ctx, id, r.client, keyID, &diags)
		if diags.HasError() {
			for _, d := range diags {
				resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
			}
		}
	}

	refreshResponse, err := r.client.PostNoData(ctx, id, common.URL_OCI+"/keys/"+keyID+"/refresh")
	if err != nil {
		msg := "Error refreshing OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		resp.Diagnostics.AddWarning(details, "")
		tflog.Error(ctx, details)
	} else {
		response = refreshResponse
		tflog.Trace(ctx, "[resource_resource_oci_key.go -> Create][response:"+response)
	}

	var diags diag.Diagnostics
	setKeyState(ctx, id, r.client, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceCCKMOCIKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_key.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_key.go -> Read]["+id+"]")

	var state models.KeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()

	response, err := r.client.GetById(ctx, id, keyID, common.URL_OCI+"/keys")
	if err != nil {
		msg := "Error reading OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[resource_resource_oci_key.go -> Read][response:"+response)
	setKeyState(ctx, id, r.client, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *resourceCCKMOCIKey) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_key.go -> ImportState]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_key.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *resourceCCKMOCIKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_key.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_key.go -> Update]["+id+"]")

	var plan models.KeyTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state models.KeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()

	updateKey(ctx, id, r.client, keyID, &plan.KeyCommonTFSDK, &state.KeyCommonTFSDK, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, keyID, common.URL_OCI+"/keys")
	if err != nil {
		msg := "Error reading OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[resource_oci_key.go -> Update][response:"+response)
	setKeyState(ctx, id, r.client, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceCCKMOCIKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_key.go -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_key.go -> Delete]["+id+"]")
	var state models.KeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()

	days := state.ScheduleForDeletionDays.ValueInt64()
	deleteKey(ctx, id, r.client, keyID, days, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
}

func setKeyState(ctx context.Context, id string, client *common.Client, response string, state *models.KeyTFSDK, diags *diag.Diagnostics) {
	setCommonKeyState(ctx, id, client, response, &state.KeyCommonTFSDK, diags)
	if diags.HasError() {
		return
	}
	state.VaultID = types.StringValue(gjson.Get(response, "vault_id").String())
	if state.KeyParams.LifecycleState.ValueString() == "ENABLED" {
		state.EnableKey = types.BoolValue(true)
	} else {
		state.EnableKey = types.BoolValue(false)
	}
	state.Vault = types.StringValue(gjson.Get(response, "cckm_vault_id").String())
}
