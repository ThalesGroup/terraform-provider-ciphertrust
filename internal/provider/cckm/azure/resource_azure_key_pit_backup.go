package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceAzureKeyPitBackup{}
	_ resource.ResourceWithConfigure = &resourceAzureKeyPitBackup{}
)

// NewResourceAzureKeyPitBackup returns a new instance of the ciphertrust_azure_key_pit_backup resource.
func NewResourceAzureKeyPitBackup() resource.Resource {
	return &resourceAzureKeyPitBackup{}
}

type resourceAzureKeyPitBackup struct {
	client *common.Client
}

func (r *resourceAzureKeyPitBackup) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_key_pit_backup"
}

func (r *resourceAzureKeyPitBackup) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAzureKeyPitBackup) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	nonBlank := []validator.String{
		stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character"),
	}
	immutableOptional := []planmodifier.String{
		stringplanmodifier.RequiresReplace(),
		stringplanmodifier.UseStateForUnknown(),
	}
	resp.Schema = schema.Schema{
		Description: "Use this resource to create a Point In Time (PIT) backup of an Azure key. " +
			"Each time the trigger value changes, one new backup is created in CipherTrust Manager. " +
			"Destroying this resource does not delete the backup, it remains in CipherTrust Manager and can be used " +
			"to restore the key with the restore_key block of ciphertrust_azure_key. " +
			"Only create one ciphertrust_azure_key_pit_backup resource per key. " +
			"To take another backup of the same key, change the trigger value of the existing resource. " +
			"This resource cannot be imported.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "CipherTrust Manager resource ID of the PIT backup. Use it as restore_key.backup_id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"key_id": schema.StringAttribute{
				Required:      true,
				Description:   "(Immutable) CipherTrust Manager resource ID of the Azure key to back up.",
				Validators:    nonBlank,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"trigger": schema.StringAttribute{
				Required: true,
				Description: "Arbitrary user-supplied value that controls when a backup is taken. " +
					"Changing this value replaces the resource, which creates one additional backup.",
				Validators:    nonBlank,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "(Immutable) Name for the backup.",
				PlanModifiers: immutableOptional,
			},
			"description": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "(Immutable) Description for the backup.",
				PlanModifiers: immutableOptional,
			},
			"uri": schema.StringAttribute{
				Computed:      true,
				Description:   "CipherTrust Manager URI of the backup.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"account": schema.StringAttribute{
				Computed:      true,
				Description:   "CipherTrust Manager account of the backup.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant": schema.StringAttribute{
				Computed:      true,
				Description:   "Azure tenant ID of the key.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"type": schema.StringAttribute{
				Computed:      true,
				Description:   "Type of the backup.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"backup": schema.StringAttribute{
				Computed:      true,
				Description:   "Opaque identifier of the backup data held by CipherTrust Manager.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"key_name": schema.StringAttribute{
				Computed:      true,
				Description:   "Name of the backed up key.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"key_vault": schema.StringAttribute{
				Computed:      true,
				Description:   "Key vault of the backed up key in the form <vault name>::<subscription ID>.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"vault_name": schema.StringAttribute{
				Computed:      true,
				Description:   "Name of the Azure key vault.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"subscription_id": schema.StringAttribute{
				Computed:      true,
				Description:   "Azure subscription ID of the key vault.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"subscription_name": schema.StringAttribute{
				Computed:      true,
				Description:   "Azure subscription name of the key vault.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"region": schema.StringAttribute{
				Computed:      true,
				Description:   "Azure region of the key vault.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"cloud_name": schema.StringAttribute{
				Computed:      true,
				Description:   "Azure cloud of the key vault.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{
				Computed:      true,
				Description:   "Date and time the backup was created in CipherTrust Manager.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"updated_at": schema.StringAttribute{
				Computed:      true,
				Description:   "Date and time the backup was last updated in CipherTrust Manager.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"gone": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the backed up key no longer exists in Azure.",
			},
		},
	}
}

// Create takes one PIT backup of the key. It is serialised per key because several resources may
// target the same key.
func (r *resourceAzureKeyPitBackup) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_key_pit_backup.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_key_pit_backup.go -> Create][" + id + "]")

	var plan models.AzureKeyPitBackupTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := plan.KeyID.ValueString()

	mutexKey := fmt.Sprintf("azure-key-pit-backup-%s", keyID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	body := map[string]interface{}{}
	if !plan.Name.IsNull() && !plan.Name.IsUnknown() {
		body["name"] = plan.Name.ValueString()
	}
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		body["description"] = plan.Description.ValueString()
	}
	payload, err := json.Marshal(body)
	if err != nil {
		msg := "Error creating Azure key PIT backup, invalid payload."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	response, err := azurePostDataV2WithRetry(ctx, id, r.client, azureKeysEndpoint+"/"+keyID+"/backups", payload)
	if err != nil {
		msg := "Error creating Azure key PIT backup."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.client.Log.Debug("[resource_azure_key_pit_backup.go -> Create][response:" + response + "]")
	if gjson.Get(response, "id").String() == "" {
		msg := "Error creating Azure key PIT backup, the response did not contain a backup ID."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	azureKeyPitBackupSetState(response, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the backup. If it no longer exists a warning is added and the resource is removed
// from state, so the next apply takes a new backup.
func (r *resourceAzureKeyPitBackup) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_key_pit_backup.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_key_pit_backup.go -> Read][" + id + "]")

	var state models.AzureKeyPitBackupTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	backupID := state.ID.ValueString()

	response, err := r.client.GetById(ctx, id, backupID, azureKeysEndpoint+"/"+keyID+"/backups")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			msg := "Azure key PIT backup was not found. It will be removed from state."
			details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "backup_id": backupID})
			r.client.Log.Warn(details)
			resp.Diagnostics.AddWarning(details, "")
			resp.State.RemoveResource(ctx)
			return
		}
		msg := "Error reading Azure key PIT backup."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "backup_id": backupID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	azureKeyPitBackupSetState(response, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update is a no-op. Every input attribute (key_id, trigger, name, description) forces
// replacement, so Update should never be called in practice.
func (r *resourceAzureKeyPitBackup) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
}

// Delete is a no-op. Removing this resource from state does not delete the backup, it is kept
// in CipherTrust Manager.
func (r *resourceAzureKeyPitBackup) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// azureKeyPitBackupSetState copies the backup response into state. The trigger and key_id are kept.
func azureKeyPitBackupSetState(response string, state *models.AzureKeyPitBackupTFSDK) {
	str := func(field string) types.String { return types.StringValue(gjson.Get(response, field).String()) }
	state.ID = str("id")
	state.Name = str("name")
	state.Description = str("description")
	state.URI = str("uri")
	state.Account = str("account")
	state.Tenant = str("tenant")
	state.Type = str("type")
	state.Backup = str("backup")
	state.KeyName = str("key_name")
	state.KeyVault = str("key_vault")
	state.VaultName = str("vault_name")
	state.SubscriptionID = str("subscription_id")
	state.SubscriptionName = str("subscription_name")
	state.Region = str("region")
	state.CloudName = str("cloud_name")
	state.CreatedAt = str("createdAt")
	state.UpdatedAt = str("updatedAt")
	state.Gone = types.BoolValue(gjson.Get(response, "gone").Bool())
}
