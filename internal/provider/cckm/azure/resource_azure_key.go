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

var (
	azureKeyTypes  = []string{"EC", "EC-HSM", "RSA", "RSA-HSM"}
	azureKeyCurves = []string{"P-256", "P-384", "P-521", "SECP256K1"}
	azureKeyOps    = []string{"encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey", "import"}
)

func (r *resourceCCKMAzureKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to add a key to a CipherTrust Manager Azure vault. " +
			"The mode is chosen by which block is set. Only one block can be set.\n\n" +
			"- No block (default): creates a new native Azure key in the vault from name and azure_params.\n" +
			"- upload_key: uploads key material to the vault.\n" +
			"- restore_key: restores an existing key that has a backup into the vault nominated by vault_id.\n\n" +
			"All inputs are immutable except `azure_params.tags`, `azure_params.key.key_ops`, and " +
			"`azure_params.attributes.enabled`, `azure_params.attributes.activation_date` and `azure_params.attributes.expiration_date`.\n\n" +
			"To create a new version of a key, create another key resource with the same name.\n\n" +
			"If a soft-deleted key of the same name exists in the vault, creating the resource recovers it " +
			"instead of creating a new key. This requires `recover_soft_deleted_keys` to be true in the " +
			"provider settings, otherwise the create fails.\n\n" +
			"On destroy, the key is soft-deleted and, if the vault supports purging and `purge_keys_on_delete` " +
			"is true in the provider settings (the default), purged. If it is false, the key is only soft-deleted. " +
			"After a purge, the key backups are deleted from CipherTrust Manager unless " +
			"`retain_key_backups_after_purge` is true in the provider settings.",
		Attributes: map[string]schema.Attribute{
			// User inputs.
			"vault_id": schema.StringAttribute{
				Required: true,
				Description: "(Conditionally immutable) CipherTrust Manager resource ID of the Azure vault that contains the key. " +
					"Can only be changed if the previously configured vault no longer exists in CipherTrust Manager. " +
					"A vault name is not accepted.",
				Validators: []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
			},
			"name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "(Immutable) Name of the key. May contain only alphanumeric characters and hyphens. " +
					"Required unless restore_key is set. Uploading a key with the name of an existing key adds a new version to that key.",
				Validators: []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
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
							"activation_date": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Description: "Date of key activation in UTC time in RFC3339 format. For example, 2026-07-03T14:24:00Z. " +
									"Before this time the key cannot be used. A date cannot be cleared once it is set",
								Validators:    []validator.String{validators.RFC3339()},
								PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							},
							"expiration_date": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Description: "Date of key expiry in UTC time in RFC3339 format. For example, 2030-07-03T14:24:00Z. " +
									"Must be later than activation_date. A date cannot be cleared once it is set.",
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
						Validators:  []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
					},
					"backup_id": schema.StringAttribute{
						Optional: true,
						Description: "CipherTrust Manager resource ID of a PIT backup. " +
							"If not set, the latest backup of the key is restored. " +
							"The Point In Time (PIT) backup IDs of a key can be listed with the `ciphertrust_azure_key_pit_backup_list` data source. " +
							"Point In Time backups can be created for a key using the ciphertrust_azure_pit_backup resource.",
						Validators: []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
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
						Validators: []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
					},
					"pfx": schema.StringAttribute{
						Optional: true,
						Description: "Path to the PFX file to upload. The file is read and sent to CipherTrust Manager " +
							"when the key is created. Only the path is stored in state. " +
							"Required when source_key_tier is pfx, and cannot be set otherwise.",
						Validators: []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
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
						Validators: []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
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
						Validators:  []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
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
						Validators:  []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
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
				Computed: true,
				Description: "CipherTrust Manager resource ID of the Azure key backup." +
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
			"managed": schema.BoolAttribute{
				Computed: true,
				Description: "True if the lifetime of the key is managed by the key vault, for example a key that " +
					"backs a certificate. False if the API does not return the value.",
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
	r.client.Log.Debug("[resource_azure_key.go -> Create][response:" + redactAzureKeyResponse(response) + "]")
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
	r.client.Log.Debug("[resource_azure_key.go -> Read][response:" + redactAzureKeyResponse(response) + "]")

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

	// vault_id is conditionally immutable. When it was repointed because the old vault no longer exists,
	// the response may still carry the old vault, so the planned value is kept.
	plannedVaultID := plan.VaultID
	azureKeyUpdate(ctx, id, r.client, &plan, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.VaultID = plannedVaultID
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// azureKeyPurgeable is the text in the recovery level of keys in a vault that allows purging.
const azureKeyPurgeable = "Purgeable"

// azureKeyLatestVersion lists the latest version of a key. It returns the list response and
// the ID of the latest version, which is "" when the key is not found.
func azureKeyLatestVersion(ctx context.Context, id string, client *common.Client, vaultID string, keyName string) (string, string, error) {
	filters := url.Values{}
	filters.Set("key_name", keyName)
	filters.Set("key_vault_id", vaultID)
	filters.Set("version", "-1")
	listJSON, err := client.ListWithFilters(ctx, id, azureKeysEndpoint, filters)
	if err != nil {
		return "", "", err
	}
	return listJSON, gjson.Get(listJSON, "resources.0.id").String(), nil
}

// Delete deletes an Azure key.
//   - If the key is not found it is removed from state with a warning.
//   - If the key is not the latest version of the key name, nothing is done in Azure and the
//     resource is removed from state.
//   - Delete is repeatable. Each call does only what is left to do, using the provider settings
//     at the time of the call, so a destroy operation that failed part way can be run again.
//   - If the key is not soft-deleted or purged it is soft-deleted. Failure is an error.
//   - If the key is not purged, is purgeable and purge_keys_on_delete is true, it is purged.
//     A purge straight after a soft-delete is expected to return 409 until Azure has finished,
//     so the purge is retried. Failure is an error.
//   - If the key is purged (now or by an earlier call) and retain_key_backups_after_purge is
//     false, the key backups are deleted. This makes no Azure call, it only removes the key
//     and its versions from the CCKM database, so it is not retried on 409. Failing to delete
//     backups is a warning.
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

	vaultID := gjson.Get(response, "key_vault_id").String()
	keyName := gjson.Get(response, "key_name").String()

	mutexKey := fmt.Sprintf("azure-key-%s", vaultID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	if vaultID != "" && keyName != "" {
		_, latestID, err := azureKeyLatestVersion(ctx, id, r.client, vaultID, keyName)
		if err != nil {
			msg := "Error deleting Azure key, failed to list the latest version of the key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "name": keyName})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		if latestID != keyID {
			r.client.Log.Info("[resource_azure_key.go -> Delete][" + id + "] Key " + keyID + " is not the latest version of " + keyName + ", not deleting in Azure")
			return
		}
	}

	settings := r.client.CCKMConfig.AzureCCKMSettings
	purged := gjson.Get(response, "deleted").Bool()
	softDeleted := gjson.Get(response, "key_soft_deleted_in_azure").Bool()

	if !purged && !softDeleted {
		_, err := azurePostNoDataWithRetry(ctx, id, r.client, azureKeysEndpoint+"/"+keyID+"/soft-delete")
		if err != nil {
			msg := "Error soft deleting Azure key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		r.client.Log.Info("[resource_azure_key.go -> Delete][" + id + "] Soft deleted Azure key " + keyName)
	}

	if !purged {
		purgeable := strings.Contains(gjson.Get(response, "azure_param.attributes.recoveryLevel").String(), azureKeyPurgeable)
		if !purgeable {
			r.client.Log.Info("[resource_azure_key.go -> Delete][" + id + "] Not purging " + keyName + " as the key is not purgeable")
		} else if !settings.PurgeKeysOnDelete {
			r.client.Log.Info("[resource_azure_key.go -> Delete][" + id + "] Not purging " + keyName + " as purge_keys_on_delete is false")
		} else {
			purgeResp, err := azurePostNoDataWithRetry(ctx, id, r.client, azureKeysEndpoint+"/"+keyID+"/hard-delete")
			if err != nil {
				msg := "Error purging Azure key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				r.client.Log.Error(details)
				resp.Diagnostics.AddError(details, "")
				return
			}
			r.client.Log.Info("[resource_azure_key.go -> Delete][" + id + "] Purged Azure key " + keyName)
			purged = gjson.Get(purgeResp, "deleted").Bool()
		}
	}

	if !purged {
		r.client.Log.Info("[resource_azure_key.go -> Delete][" + id + "] Not deleting backups of " + keyName + " as the key is not purged")
		return
	}

	if settings.RetainKeyBackupsAfterPurge {
		r.client.Log.Info("[resource_azure_key.go -> Delete][" + id + "] Not deleting backups of " + keyName + " as retain_key_backups_after_purge is true")
		return
	}

	// Backups are deleted only when this key is still the latest version and it is purged.
	listJSON, latestID, err := azureKeyLatestVersion(ctx, id, r.client, vaultID, keyName)
	if err != nil || latestID != keyID || !gjson.Get(listJSON, "resources.0.deleted").Bool() {
		return
	}
	if _, err = r.client.PostNoData(ctx, id, azureKeysEndpoint+"/"+keyID+"/delete-backup"); err != nil {
		msg := "Failed to delete the key backups of " + keyName + "."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddWarning(details, "")
		return
	}
	r.client.Log.Info("[resource_azure_key.go -> Delete][" + id + "] Deleted backups of Azure key " + keyName)
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
		var state models.AzureKeyTFSDK
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if !azureVaultChangeAllowed(ctx, uuid.New().String(), r.client, state.VaultID, plan.VaultID, &resp.Diagnostics) {
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

// redactAzureKeyResponse returns a safe-to-log version of an Azure key API response. key_vault has the form
// <vault name>::<subscription id>, only the subscription id is redacted.
func redactAzureKeyResponse(response string) string {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(response), &data); err != nil {
		return response
	}
	if keyVault, ok := data["key_vault"].(string); ok {
		if name, _, found := strings.Cut(keyVault, "::"); found {
			data["key_vault"] = name + "::redacted"
		}
	}
	for _, field := range []string{"azure_vault_id", "subscription_id", "tenant"} {
		if _, ok := data[field]; ok {
			data[field] = "redacted"
		}
	}
	if azureParam, ok := data["azure_param"].(map[string]interface{}); ok {
		if _, ok := azureParam["tags"]; ok {
			azureParam["tags"] = "redacted"
		}
	}
	b, err := json.Marshal(data)
	if err != nil {
		return response
	}
	return string(b)
}
