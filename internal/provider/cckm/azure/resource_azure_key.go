package cckm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/validators"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

const (
	azureManagedHSMVaultType = "Microsoft.KeyVault/managedHSMs"
	// azureKeySoftDeleted is the CipherTrust Manager status of a soft deleted key.
	azureKeySoftDeleted = "SOFT-DELETED"
	// azureKeysEndpoint is the CipherTrust Manager endpoint for Azure keys.
	azureKeysEndpoint = common.URL_AZURE + "/keys"
	// azureUploadKeyEndpoint is the CipherTrust Manager endpoint that uploads a key to Azure.
	azureUploadKeyEndpoint = common.URL_AZURE + "/upload-key"
	// azureSourceKeyTierPfx is the upload_key source key tier that uploads a key from a PFX file.
	// Every other source key tier uploads a key that is held in CipherTrust Manager.
	azureSourceKeyTierPfx = "pfx"
)

var (
	_ resource.Resource               = &resourceCCKMAzureKey{}
	_ resource.ResourceWithConfigure  = &resourceCCKMAzureKey{}
	_ resource.ResourceWithModifyPlan = &resourceCCKMAzureKey{}

	_ resource.ResourceWithImportState = &resourceCCKMAzureKey{}
)

// NewResourceCCKMAzureKey returns a new instance of the ciphertrust_azure_key resource.
func NewResourceCCKMAzureKey() resource.Resource {
	return &resourceCCKMAzureKey{}
}

type resourceCCKMAzureKey struct {
	client *common.Client
}

func (r *resourceCCKMAzureKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_key"
}

func (r *resourceCCKMAzureKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCCKMAzureKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create a native Azure key in a CipherTrust Manager Azure vault, " +
			"to upload key material into a vault (upload_key), or to restore an existing key into a vault " +
			"(restore_key). New versions of a key are created by creating another key resource with the same name.",
		Attributes: map[string]schema.Attribute{
			// User inputs.
			"vault_id": schema.StringAttribute{
				Required: true,
				Description: "(Immutable) CipherTrust Manager resource ID of the Azure vault that contains the key. " +
					"A vault name is not accepted.",
				Validators:    []validator.String{azureKeyNonBlank()},
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
			},
			"name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "(Immutable) Name of the key. May contain only alphanumeric characters and hyphens. " +
					"Required unless restore_key is set. Uploading a key with the name of an existing key adds a new version to that key.",
				Validators: []validator.String{azureKeyNonBlank()},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableString(),
				},
			},
			"azure_params": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Description: "Azure key parameters. Required unless restore_key is set, in which case it must not " +
					"be configured and is populated from the restored key.",
				PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
				Attributes: map[string]schema.Attribute{
					"key": schema.SingleNestedAttribute{
						Optional:      true,
						Computed:      true,
						Description:   "Key type, curve and permitted operations.",
						PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
						Attributes: map[string]schema.Attribute{
							"kty": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Description: "(Immutable) Key type. Options are EC, EC-HSM, RSA and RSA-HSM. " +
									"The HSM types require a premium or managed HSM vault. Cannot be set when upload_key is set.",
								Validators: []validator.String{stringvalidator.OneOf(azureKeyTypes...)},
								PlanModifiers: []planmodifier.String{
									stringplanmodifier.UseStateForUnknown(),
									modifiers.ImmutableString(),
								},
							},
							"curve": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Description: "(Immutable) Elliptic curve name for EC and EC-HSM keys. Options are P-256, " +
									"P-384, P-521 and SECP256K1. Required for EC key types and not allowed for RSA key types. " +
									"Cannot be set when upload_key is set.",
								Validators: []validator.String{stringvalidator.OneOf(azureKeyCurves...)},
								PlanModifiers: []planmodifier.String{
									stringplanmodifier.UseStateForUnknown(),
									modifiers.ImmutableString(),
								},
							},
							"key_ops": schema.ListAttribute{
								Optional:    true,
								Computed:    true,
								ElementType: types.StringType,
								Description: "Operations permitted for the key. Options are encrypt, decrypt, sign, " +
									"verify, wrapKey, unwrapKey and import. The import operation is only valid for RSA-HSM keys. " +
									"Can be updated. Removing key_ops from the configuration keeps the current operations.",
								Validators:    []validator.List{listvalidator.ValueStringsAre(stringvalidator.OneOf(azureKeyOps...))},
								PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()},
							},
							"kid": schema.StringAttribute{
								Computed:      true,
								Description:   "The Azure key identifier of the key version.",
								PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							},
							"n": schema.StringAttribute{
								Computed:      true,
								Description:   "RSA modulus of the public key.",
								PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							},
							"e": schema.StringAttribute{
								Computed:      true,
								Description:   "RSA public exponent of the public key.",
								PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							},
						},
					},
					"attributes": schema.SingleNestedAttribute{
						Optional:      true,
						Computed:      true,
						Description:   "Key attributes.",
						PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Optional:      true,
								Computed:      true,
								Description:   "Whether the key is enabled in Azure. Can be updated.",
								PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
							},
							"expiration_date": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Description: "(Updateable) Date of key expiry in UTC time in RFC3339 format. For example, 2030-07-03T14:24:00Z. " +
									"Must be later than activation_date. " +
									"A date cannot be removed once it is set: removing it from the " +
									"configuration keeps the current value.",
								Validators:    []validator.String{validators.RFC3339()},
								PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							},
							"activation_date": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Description: "(Updateable) Date of key activation in UTC time in RFC3339 format. For example, 2026-07-03T14:24:00Z. " +
									"Before this time the key cannot be used. " +
									"A date cannot be removed once it is set: removing it from the " +
									"configuration keeps the current value.",
								Validators:    []validator.String{validators.RFC3339()},
								PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							},
							"recovery_level": schema.StringAttribute{
								Computed:      true,
								Description:   "Deletion recovery level currently in effect for the key in Azure.",
								PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							},
							"created": schema.Int64Attribute{
								Computed:      true,
								Description:   "Creation time in Unix epoch seconds.",
								PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
							},
							"updated": schema.Int64Attribute{
								Computed:    true,
								Description: "Last update time in Unix epoch seconds.",
							},
						},
					},
					"key_size": schema.Int64Attribute{
						Optional: true,
						Computed: true,
						Description: "(Immutable) Key size in bits for RSA and RSA-HSM keys. Options are 2048, 3072 and 4096. " +
							"Required for RSA key types and not allowed for EC key types. Cannot be set when upload_key is set.",
						Validators: []validator.Int64{int64validator.OneOf(2048, 3072, 4096)},
						PlanModifiers: []planmodifier.Int64{
							int64planmodifier.UseStateForUnknown(),
							modifiers.ImmutableInt64(),
						},
					},
					"tags": schema.MapAttribute{
						Optional:    true,
						Computed:    true,
						ElementType: types.StringType,
						Description: "Tags to apply to the key as key:value pairs. Can be updated: tags missing from the " +
							"configuration are removed from the key. Removing the tags attribute keeps the current tags; " +
							"set tags = {} to remove all tags.",
						PlanModifiers: []planmodifier.Map{mapplanmodifier.UseStateForUnknown()},
					},
				},
			},
			"restore_key": schema.SingleNestedAttribute{
				Optional: true,
				Description: "(Immutable) Restores an existing key that has a backup into the vault instead of creating a new key. " +
					"No other key attributes may be configured. Cannot be combined with upload_key.",
				PlanModifiers: []planmodifier.Object{modifiers.ImmutableObject()},
				Attributes: map[string]schema.Attribute{
					"key_id": schema.StringAttribute{
						Required:    true,
						Description: "CipherTrust Manager resource ID of the existing key to restore.",
						Validators:  []validator.String{azureKeyNonBlank()},
					},
					"backup_id": schema.StringAttribute{
						Optional: true,
						Description: "CipherTrust Manager resource ID of a PIT backup. " +
							"If not set, the latest backup of the key is restored. " +
							"The Point In Time (PIT) backup IDs of a key can be listed with the `ciphertrust_azure_key_pit_backup_list` data source. " +
							"Point In Time backups can be created for a key using the ciphertrust_azure_pit_backup resource.",
						Validators: []validator.String{azureKeyNonBlank()},
					},
				},
			},
			"upload_key": schema.SingleNestedAttribute{
				Optional: true,
				Description: "(Immutable) Uploads key material to the vault instead of creating a new key. " +
					"Cannot be combined with restore_key. The azure_params kty, curve and key_size cannot be set; " +
					"they are reported by Azure after the upload.",
				PlanModifiers: []planmodifier.Object{modifiers.ImmutableObjectExceptWriteOnly("local_key_name")},
				Attributes: map[string]schema.Attribute{
					"source_key_tier": schema.StringAttribute{
						Required: true,
						Description: "Source of the key material to upload. Options are local and pfx. " +
							"local uploads a key that exists in CipherTrust Manager and requires source_key_id. " +
							"pfx uploads a key from a PFX file and requires pfx.",
						Validators: []validator.String{stringvalidator.OneOf("local", "pfx")},
					},
					"source_key_id": schema.StringAttribute{
						Optional: true,
						Description: "Identifier of the CipherTrust Manager key to upload. " +
							"Required unless source_key_tier is pfx, and cannot be set when it is.",
						Validators: []validator.String{azureKeyNonBlank()},
					},
					"pfx": schema.StringAttribute{
						Optional: true,
						Description: "Path to the PFX file to upload. The file is read and sent to CipherTrust Manager " +
							"when the key is created. Only the path is stored in state. " +
							"Required when source_key_tier is pfx, and cannot be set otherwise.",
						Validators: []validator.String{azureKeyNonBlank()},
					},
					"pfx_password": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "Password of the PFX file. Can only be set when source_key_tier is pfx.",
					},
					"kek_kid": schema.StringAttribute{
						Optional: true,
						Description: "CipherTrust Manager ID of the key encryption key (KEK) that wraps the " +
							"key material during the upload. It is not an Azure key URL. Applies only to premium and managed HSM vaults. " +
							"The KEK must be an RSA-HSM key of 2048, 3072 or 4096 bits in the same vault, with import as its only key operation. " +
							"If not set, a temporary KEK is created.",
						Validators: []validator.String{azureKeyNonBlank()},
					},
					"hsm": schema.BoolAttribute{
						Optional: true,
						Description: "Set to true to create an HSM key. The vault must be a premium or managed HSM vault. " +
							"If not set, a software key is created.",
					},
					"local_key_name": schema.StringAttribute{
						Computed:      true,
						Description:   "Name of the CipherTrust Manager key that was uploaded. Set only when source_key_tier is local.",
						PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
					},
				},
			},
			"exportable": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "(Immutable) Whether the private key can be exported from Azure. The vault must be a premium " +
					"or managed HSM vault. If true, release_policy must also be set.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableBool(),
				},
			},
			"release_policy": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "(Immutable) Key release policy as a JSON object string. " +
					"Must be set if exportable is true.",
				Validators: []validator.String{validators.JSONObject()},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableJSONString(),
				},
			},
			"enable_auto_rotation": schema.SingleNestedAttribute{
				Optional: true,
				Description: "Enable the key for a scheduled rotation job. Cannot be set at creation time; configure via update " +
					"after the key is created. Removing the block disables the rotation job.",
				Attributes: map[string]schema.Attribute{
					"job_config_id": schema.StringAttribute{
						Required:    true,
						Description: "CipherTrust Manager resource ID of a key rotation scheduler.",
						Validators:  []validator.String{azureKeyNonBlank()},
					},
					"key_source": schema.StringAttribute{
						Required: true,
						Description: "Source of the key material of the new key version. Options are native and ciphertrust. " +
							"key_type EC and EC-HSM require native.",
						Validators: []validator.String{stringvalidator.OneOf("native", "ciphertrust")},
					},
					"key_type": schema.StringAttribute{
						Required: true,
						Description: "Type of the new key version. Options are RSA, EC, RSA-HSM and EC-HSM. " +
							"EC and EC-HSM require key_source native. " +
							"RSA-HSM and EC-HSM require a Premium vault.",
						Validators: []validator.String{stringvalidator.OneOf("RSA", "EC", "RSA-HSM", "EC-HSM")},
					},
					"key_size": schema.Int64Attribute{
						Optional:    true,
						Description: "Size of the new key version. Options are 2048, 3072 and 4096. Required when key_type is RSA or RSA-HSM.",
						Validators:  []validator.Int64{int64validator.OneOf(2048, 3072, 4096)},
					},
					"ec_name": schema.StringAttribute{
						Optional:    true,
						Description: "Curve of the new key version. Options are P-256, P-384, P-521 and SECP256K1. Required when key_type is EC or EC-HSM.",
						Validators:  []validator.String{stringvalidator.OneOf("P-256", "P-384", "P-521", "SECP256K1")},
					},
					"enable_key": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Whether the new key version is enabled. Default is true.",
						Default:     booldefault.StaticBool(true),
					},
					"release_policy": schema.StringAttribute{
						Optional:    true,
						Description: "Key release policy of the new key version as a JSON object string.",
						Validators:  []validator.String{validators.JSONObject()},
					},
				},
			},
			"enable_auto_backup": schema.SingleNestedAttribute{
				Optional: true,
				Description: "Enable the key for a scheduled backup job. Cannot be set at creation time; configure via update " +
					"after the key has been created. Removing the block disables the backup job.",
				Attributes: map[string]schema.Attribute{
					"job_config_id": schema.StringAttribute{
						Required:    true,
						Description: "CipherTrust Manager resource ID of a cckm_key_backup scheduler.",
						Validators:  []validator.String{azureKeyNonBlank()},
					},
				},
			},

			// Computed attributes.
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The key's CipherTrust Manager resource ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"account": schema.StringAttribute{
				Computed:      true,
				Description:   "The account which owns this resource.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"backup": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
				Description: "CipherTrust Manager opaque object ID holding the automatic backup of the key. " +
					"CipherTrust Manager takes this backup when the key is created, updated or uploaded. " +
					"It is not a PIT backup ID and cannot be used as restore_key.backup_id.",
			},
			"backup_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date and time the key was last backed up.",
			},
			"cloud_name": schema.StringAttribute{
				Computed:      true,
				Description:   "CipherTrust Manager cloud name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{
				Computed:      true,
				Description:   "Date and time the key was created in CipherTrust Manager.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"deleted": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the key has been deleted.",
			},
			"key_material_origin": schema.StringAttribute{
				Computed:      true,
				Description:   "The origin of the key material.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"key_soft_deleted_in_azure": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the key is soft deleted in Azure.",
			},
			"labels": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key:value pairs associated with the key. When a scheduler job is enabled for the key, " +
					"the labels contain entries describing the job.",
			},
			"backup_config": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Backup scheduler configuration of the key. When a backup job is enabled for the key, " +
					"it contains backup_job_config_id.",
			},
			"region": schema.StringAttribute{
				Computed:      true,
				Description:   "Azure region of the vault in which the key resides.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"soft_delete_enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether soft delete is enabled for the key's vault.",
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Status of the key in CipherTrust Manager.",
			},
			"synced_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date and time the key was last synchronized.",
			},
			"tenant": schema.StringAttribute{
				Computed:      true,
				Description:   "The Azure tenant of the key.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date and time the key was last updated in CipherTrust Manager.",
			},
			"version": schema.StringAttribute{
				Computed:    true,
				Description: "The Azure version identifier of the key.",
			},
			"version_count": schema.Int64Attribute{
				Computed:    true,
				Description: "The number of versions of the key.",
			},
			"vault_name": schema.StringAttribute{
				Computed:      true,
				Description:   "The vault's name and subscription ID in the form <vault name>::<subscription id>.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

// Create creates a new Azure key. restore_key restores an existing key, upload_key uploads key material,
// otherwise a native key is created.
// The vault is always fetched first so that vault_id is confirmed to be a CipherTrust Manager vault
// resource ID; a vault name is rejected.
func (r *resourceCCKMAzureKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_key.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_key.go -> Create][" + id + "]")

	var plan models.AzureKeyTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vaultID := plan.VaultID.ValueString()

	vaultResp := getAzureVault(ctx, id, r.client, vaultID, "creating key in", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if gjson.Get(vaultResp, "id").String() != vaultID {
		msg := "Error creating Azure key: vault_id must be the CipherTrust Manager resource ID of an Azure vault."
		details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	vaultName := gjson.Get(vaultResp, "azure_name").String() + "::" + gjson.Get(vaultResp, "subscription_id").String()

	mutexKey := fmt.Sprintf("azure-key-%s", vaultID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	var response string
	switch {
	case plan.RestoreKey != nil:
		response = restoreAzureKey(ctx, id, r.client, plan.RestoreKey.KeyID.ValueString(), plan.RestoreKey.BackupID.ValueString(), vaultID, &resp.Diagnostics)
	case plan.UploadKey != nil:
		response = uploadAzureKey(ctx, id, r.client, &plan, &resp.Diagnostics)
	default:
		response = createAzureKey(ctx, id, r.client, &plan, gjson.Get(vaultResp, "type").String(), &resp.Diagnostics)
	}
	if response == "" || resp.Diagnostics.HasError() {
		return
	}

	keyID := gjson.Get(response, "id").String()
	if keyID == "" {
		msg := "Error creating Azure key, the response did not contain a key ID."
		details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	plan.ID = types.StringValue(keyID)

	// The key exists from here on. A failure to refresh is a warning so the key is stored in state.
	getResp, getErr := r.client.GetById(ctx, id, keyID, azureKeysEndpoint)
	if getErr != nil {
		msg := "Error reading Azure key after creation. State is set from the create response."
		details := utils.ApiError(msg, map[string]interface{}{"error": getErr.Error(), "key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddWarning(details, "")
	} else {
		response = getResp
	}
	r.client.Log.Debug("[resource_azure_key.go -> Create][response:" + response + "]")
	plan.VaultName = types.StringValue(vaultName)

	var diags diag.Diagnostics
	azureKeySetState(ctx, response, &plan, &diags)
	for _, d := range diags {
		if d.Severity() == diag.SeverityError {
			resp.Diagnostics.AddError(d.Summary(), d.Detail())
		} else {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Azure key state from CipherTrust Manager.
// The key is fetched first. A 404 is a hard error.
func (r *resourceCCKMAzureKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_key.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_key.go -> Read][" + id + "]")

	var state models.AzureKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()

	response := getAzureKey(ctx, id, r.client, keyID, "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.client.Log.Debug("[resource_azure_key.go -> Read][response:" + response + "]")

	azureKeySetState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// vault_name is not in the key response. It is empty only after an import, when it is rebuilt
	// from the vault that azureKeySetState took from key_vault_id.
	if (state.VaultName.IsNull() || state.VaultName.IsUnknown()) && !state.VaultID.IsNull() {
		vaultResp := getAzureVault(ctx, id, r.client, state.VaultID.ValueString(), "reading key in", &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.VaultName = types.StringValue(gjson.Get(vaultResp, "azure_name").String() + "::" + gjson.Get(vaultResp, "subscription_id").String())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// ImportState imports an existing Azure key into Terraform state using its CipherTrust Manager
// resource ID. Read then populates the rest of the state, including vault_id and vault_name.
func (r *resourceCCKMAzureKey) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_key.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_key.go -> ImportState][" + id + "]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// Update updates the tags, key_ops, enabled, activation_date and expiration_date of a key. See azureKeyUpdate.
func (r *resourceCCKMAzureKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_key.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_key.go -> Update][" + id + "]")

	var plan, state models.AzureKeyTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	azureKeyUpdate(ctx, id, r.client, &plan, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete soft-deletes a key and, depending on the provider settings purge_keys_on_delete and
// retain_key_backups_after_purge, purges it and deletes its backups. See azureKeyDelete.
func (r *resourceCCKMAzureKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_key.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_key.go -> Delete][" + id + "]")

	var state models.AzureKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()
	response := getAzureKey(ctx, id, r.client, keyID, "deleting", &resp.Diagnostics)
	if resp.Diagnostics.HasError() || response == "" {
		return
	}
	azureKeyDelete(ctx, id, r.client, keyID, response, &resp.Diagnostics)
}

// ModifyPlan validates the configuration when the resource is being created.
// It reads req.Config because optional+computed attributes are unknown in the plan when not configured.
//   - enable_auto_rotation and enable_auto_backup cannot be configured when a key is created, uploaded or restored.
//   - restore_key set: no other key attribute may be configured and upload_key cannot be set.
//   - upload_key set: it must be valid for its source_key_tier and kty, curve and key_size cannot be set.
//   - neither set: everything required to create a new key must be configured.
func (r *resourceCCKMAzureKey) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Destroy - nothing to validate.
	if req.Plan.Raw.IsNull() {
		return
	}
	// Update - validate the planned values of the updatable attributes.
	if !req.State.Raw.IsNull() {
		var plan models.AzureKeyTFSDK
		resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
		if resp.Diagnostics.HasError() {
			return
		}
		azureKeyValidateUpdatePlan(ctx, &plan, &resp.Diagnostics)
		azureKeyValidateRotationPlan(&plan, &resp.Diagnostics)
		return
	}

	var cfg models.AzureKeyTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	azureKeyValidateRotationCreate(&cfg, &resp.Diagnostics)
	azureKeyValidateBackupCreate(&cfg, &resp.Diagnostics)
	azureKeyValidateCreateConfig(ctx, &cfg, &resp.Diagnostics)
}

// uploadAzureKey uploads key material to a CipherTrust Manager Azure vault. Uploading a key with the name of an
// existing key adds a new version to that key. The pfx file is read and base64 encoded. exportable and
// release_policy are sent only when the key is exportable. kty, curve and key_size are not sent. hsm is sent as
// azure_param.hsm.
// On failure an error diagnostic is added and "" is returned.
func uploadAzureKey(ctx context.Context, id string, client *common.Client, plan *models.AzureKeyTFSDK, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_key.go -> uploadAzureKey][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_key.go -> uploadAzureKey][" + id + "]")

	vaultID := plan.VaultID.ValueString()
	upload := plan.UploadKey
	param, ok := azureKeyBuildParam(newAzureParamsView(plan.AzureParams), diags)
	if !ok {
		return ""
	}
	uploadParam := models.AzureUploadKeyParamJSON{KeyOps: param.KeyOps, Tags: param.Tags}
	if param.Attributes != nil {
		uploadParam.Attributes = &models.AzureUploadKeyAttributesJSON{
			Enabled:   param.Attributes.Enabled,
			NotBefore: param.Attributes.NotBefore,
			Expires:   param.Attributes.Expires,
		}
	}
	if !upload.Hsm.IsNull() && !upload.Hsm.IsUnknown() {
		hsm := upload.Hsm.ValueBool()
		uploadParam.Hsm = &hsm
	}
	payload := models.AzureUploadKeyPayloadJSON{
		KeyName:            plan.Name.ValueString(),
		KeyVault:           vaultID,
		AzureParam:         uploadParam,
		SourceKeyTier:      upload.SourceKeyTier.ValueString(),
		LocalKeyIdentifier: upload.SourceKeyID.ValueString(),
		Password:           upload.PfxPassword.ValueString(),
		KekKID:             upload.KekKid.ValueString(),
	}

	if !upload.Pfx.IsNull() && !upload.Pfx.IsUnknown() {
		contents, err := os.ReadFile(upload.Pfx.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("upload_key").AtName("pfx"), "Unable to read pfx file", err.Error())
			return ""
		}
		payload.PFX = base64.StdEncoding.EncodeToString(contents)
	}

	if plan.Exportable.ValueBool() {
		exportable := true
		payload.Exportable = &exportable
		if !plan.ReleasePolicy.IsNull() && !plan.ReleasePolicy.IsUnknown() {
			var policy map[string]interface{}
			if err := json.Unmarshal([]byte(plan.ReleasePolicy.ValueString()), &policy); err != nil {
				diags.AddAttributeError(path.Root("release_policy"), "Invalid release policy",
					"release_policy must be a valid JSON object.")
				return ""
			}
			payload.ReleasePolicy = policy
		}
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error uploading Azure key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "name": payload.KeyName})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	response, err := client.PostDataV2(ctx, id, azureUploadKeyEndpoint, payloadJSON)
	if err != nil {
		msg := "Error uploading Azure key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "name": payload.KeyName, "vault_id": vaultID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// createAzureKey creates a new key in a CipherTrust Manager Azure vault.
// vaultType is the type of the vault the key is created in.
// On failure an error diagnostic is added and "" is returned.
func createAzureKey(ctx context.Context, id string, client *common.Client, plan *models.AzureKeyTFSDK, vaultType string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_key.go -> createAzureKey][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_key.go -> createAzureKey][" + id + "]")

	createPayload, ok := azureKeyBuildCreateNativePayload(plan, vaultType, diags)
	if !ok || diags.HasError() {
		return ""
	}
	payloadJSON, err := json.Marshal(createPayload)
	if err != nil {
		msg := "Error creating Azure key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "name": createPayload.KeyName})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}

	// The first create is a single attempt. A 409 here usually means the name belongs to a soft-deleted key,
	// and retrying would only use up the timeout.
	response, err := client.PostDataV2(ctx, id, azureKeysEndpoint, payloadJSON)
	if err != nil && strings.Contains(err.Error(), "status: 409") {
		if !client.CCKMConfig.AzureCCKMSettings.RecoverSoftDeletedKeys {
			client.Log.Info("[resource_azure_key.go -> createAzureKey][" + id + "] Not recovering " + createPayload.KeyName + " as recover_soft_deleted_keys is false")
			msg := "Error creating Azure key. The key name already exists, it may be soft-deleted and recover_soft_deleted_keys is false."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "name": createPayload.KeyName, "vault_id": createPayload.KeyVault})
			client.Log.Error(details)
			diags.AddError(details, "")
			return ""
		}

		// Find the latest version of the key so it can be recovered if it is soft-deleted.
		filters := url.Values{}
		filters.Set("key_name", createPayload.KeyName)
		filters.Set("key_vault_id", createPayload.KeyVault)
		filters.Set("version", "-1")
		listJSON, listErr := client.ListWithFilters(ctx, id, azureKeysEndpoint, filters)
		if listErr != nil {
			msg := "Error creating Azure key. The key name already exists in Azure but listing keys in CipherTrust Manager failed."
			details := utils.ApiError(msg, map[string]interface{}{"error": listErr.Error(), "name": createPayload.KeyName, "vault_id": createPayload.KeyVault})
			client.Log.Error(details)
			diags.AddError(details, "")
			return ""
		}

		existingID := gjson.Get(listJSON, "resources.0.id").String()
		if existingID == "" {
			msg := "Error creating Azure key. The key name already exists in Azure but the key does not exist in CipherTrust Manager, so it cannot be recovered. Synchronize the vault keys or use a different key name."
			details := utils.ApiError(msg, map[string]interface{}{"name": createPayload.KeyName, "vault_id": createPayload.KeyVault})
			client.Log.Error(details)
			diags.AddError(details, "")
			return ""
		}

		if gjson.Get(listJSON, "resources.0.status").String() == azureKeySoftDeleted {
			client.Log.Info("[resource_azure_key.go -> createAzureKey][" + id + "] Recovering soft-deleted key " + createPayload.KeyName)
			var recoverPayload []byte
			if _, recoverErr := azurePostDataV2WithRetry(ctx, id, client, azureKeysEndpoint+"/"+existingID+"/recover", recoverPayload); recoverErr != nil {
				msg := "Error recovering soft-deleted Azure key."
				details := utils.ApiError(msg, map[string]interface{}{"error": recoverErr.Error(), "name": createPayload.KeyName, "key_id": existingID})
				client.Log.Error(details)
				diags.AddError(details, "")
				return ""
			}
		} else {
			client.Log.Info("[resource_azure_key.go -> createAzureKey][" + id + "] Azure key " + createPayload.KeyName + " has already been recovered")
		}

		// Create a new version on top of the recovered key. Azure may still be settling, so 409s are retried.
		response, err = azurePostDataV2WithRetry(ctx, id, client, azureKeysEndpoint, payloadJSON)
	}

	if err != nil {
		msg := "Error creating Azure key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "name": createPayload.KeyName, "vault_id": createPayload.KeyVault})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}

	return response
}

// restoreAzureKey restores a backed up key into a CipherTrust Manager Azure vault.
// restoreID is the CipherTrust Manager ID of the key to restore.
// backupID is the optional Azure cloud key backup ID; it is sent only when not empty.
// It is a single restore request. A restored key that is soft-deleted is not recovered.
// On failure an error diagnostic is added and "" is returned.
func restoreAzureKey(ctx context.Context, id string, client *common.Client, restoreID string, backupID string, vaultID string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_key.go -> restoreAzureKey][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_key.go -> restoreAzureKey][" + id + "]")

	payloadJSON, err := json.Marshal(models.AzureRestoreKeyPayloadJSON{
		KeyVault:              vaultID,
		AzureCloudKeyBackupID: backupID,
	})
	if err != nil {
		msg := "Error restoring Azure key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "restore_key.key_id": restoreID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	response, err := client.PostDataV2(ctx, id, azureKeysEndpoint+"/"+restoreID+"/restore", payloadJSON)
	if err != nil {
		msg := "Error restoring Azure key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "restore_key.key_id": restoreID, "vault_id": vaultID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

var (
	azureKeyTypes  = []string{"EC", "EC-HSM", "RSA", "RSA-HSM"}
	azureKeyCurves = []string{"P-256", "P-384", "P-521", "SECP256K1"}
	azureKeyOps    = []string{"encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey", "import"}
)

func azureKeyNonBlank() validator.String {
	return stringvalidator.RegexMatches(
		regexp.MustCompile(`\S`),
		"must contain at least one non-whitespace character",
	)
}
