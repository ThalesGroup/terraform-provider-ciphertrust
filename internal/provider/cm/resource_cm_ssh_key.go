package cm

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCMSSHKey{}
	_ resource.ResourceWithConfigure = &resourceCMSSHKey{}
)

func NewResourceCMSSHKey() resource.Resource {
	return &resourceCMSSHKey{}
}

type resourceCMSSHKey struct {
	client common.CMClient
}

func (r *resourceCMSSHKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_ssh_key"
}

// Schema defines the schema for the resource.
func (r *resourceCMSSHKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Adds an SSH public key to the CipherTrust Manager appliance. Supported in both initial bootstrap (provider `bootstrap = \"yes\"`) and standard credentials-based (provider `bootstrap = \"no\"`) modes. **Bootstrap mode is only available on CipherTrust Manager — this resource is implicitly unsupported on CDSPaaS.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) SSH public key to add to the CipherTrust Manager appliance.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Name assigned by CipherTrust Manager to this SSH key resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"algorithm": schema.StringAttribute{
				Computed:    true,
				Description: "SSH public key algorithm (e.g. rsa, ed25519, ecdsa), as determined by CipherTrust Manager from the supplied public key material.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key_size": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Bit length of the key, applicable to RSA keys. Reported by CipherTrust Manager based on the supplied public key material. Although marked Optional in the schema, this field is not sent to CipherTrust Manager on create/update (the API only accepts the raw public key) — any configured value is effectively ignored in favor of the value CM derives.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
					modifiers.ImmutableInt64(),
				},
			},
			"curve": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Name of the elliptic curve used by the key (applicable to EC/Ed25519 keys), as reported by CipherTrust Manager. Although marked Optional in the schema, this field is not sent to CipherTrust Manager on create/update (the API only accepts the raw public key) — any configured value is effectively ignored in favor of the value CM derives. Exact accepted/reported curve name values could not be confirmed from the swagger spec or this resource's code, so no enum validator is applied.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableString(),
				},
			},
			"username": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "System/OS username associated with this SSH key on the CipherTrust Manager appliance, as reported by CipherTrust Manager. Although marked Optional in the schema, this field is not sent to CipherTrust Manager on create/update (the API only accepts the raw public key) — any configured value is effectively ignored in favor of the value CM derives.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableString(),
				},
			},
			"public_key_encoding": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Encoding format of the public key (e.g. PEM, OpenSSH/RFC4253), as reported by CipherTrust Manager. Although marked Optional in the schema, this field is not sent to CipherTrust Manager on create/update (the API only accepts the raw public key) — any configured value is effectively ignored in favor of the value CM derives. Exact accepted/reported encoding values could not be confirmed from the swagger spec or this resource's code, so no enum validator is applied.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableString(),
				},
			},
			"fingerprint": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_at": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMSSHKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_ssh_key.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMSSHKeyTFSDK
	var payload CMSSHKeyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Key.ValueString() != "" && plan.Key.ValueString() != types.StringNull().ValueString() {
		payload.Key = plan.Key.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_ssh_key.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: SSH Key Creation",
			err.Error(),
		)
		return
	}

	resourceID, err := r.client.PostDataBootstrap(ctx, id, common.URL_SSH_KEY, payloadJSON, "id")
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "already exists") || strings.Contains(errStr, "duplicate") {
			tflog.Debug(ctx, "[resource_cm_ssh_key.go -> Create] Duplicate detected, attempting exact-match fingerprint recovery")

			// Compute fingerprint of the planned key
			targetFingerprint, fpErr := computeSSHFingerprint(plan.Key.ValueString())
			if fpErr != nil {
				tflog.Debug(ctx, "[resource_cm_ssh_key.go -> Create] Failed to compute fingerprint: "+fpErr.Error())
				resp.Diagnostics.AddError(
					"Fingerprint Calculation Error",
					"An SSH key conflict was detected, but the planned key fingerprint could not be computed: "+fpErr.Error(),
				)
				return
			}

			// Query existing keys to check if any matches the computed fingerprint
			keysJSON, listErr := r.client.GetByIdBootstrap(ctx, id, "", common.URL_SSH_KEY)
			if listErr != nil {
				tflog.Debug(ctx, "[resource_cm_ssh_key.go -> Create] Failed to list existing keys: "+listErr.Error())
				resp.Diagnostics.AddError(
					"Duplicate Recovery Failed",
					"An SSH key conflict was detected, but existing keys could not be listed for comparison: "+listErr.Error(),
				)
				return
			}

			var foundMatch bool
			var matchedID string

			// Handle "resources" array or direct array
			var keyRecords []gjson.Result
			if gjson.Get(keysJSON, "resources").Exists() {
				keyRecords = gjson.Get(keysJSON, "resources").Array()
			} else {
				parsed := gjson.Parse(keysJSON)
				if parsed.IsArray() {
					keyRecords = parsed.Array()
				} else {
					keyRecords = []gjson.Result{parsed}
				}
			}

			for _, keyRecord := range keyRecords {
				fp := keyRecord.Get("fingerprint").String()
				if fp == targetFingerprint {
					matchedID = keyRecord.Get("id").String()
					foundMatch = true
					break
				}
			}

			if foundMatch && matchedID != "" {
				tflog.Debug(ctx, "[resource_cm_ssh_key.go -> Create] Exact match found! Adopting key ID: "+matchedID)
				resourceID = matchedID
			} else {
				tflog.Debug(ctx, "[resource_cm_ssh_key.go -> Create] No exact fingerprint match found among existing keys")
				resp.Diagnostics.AddError(
					"Duplicate SSH Key Conflict",
					"An SSH key with the same name or metadata already exists on CipherTrust Manager, but has a different fingerprint. "+
						"Please choose a different key, or manually reconcile/import the existing resource.",
				)
				return
			}
		} else {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_ssh_key.go -> Create]["+id+"]")
			resp.Diagnostics.AddError(
				"Error creating SSH Key on CipherTrust Manager: ",
				"Could not create SSH Key, unexpected error: "+err.Error(),
			)
			return
		}
	}

	// Fetch the created resource to hydrate all Computed fields so that the
	// framework does not see Unknown values in state after apply.
	fullResponse, err := r.client.GetByIdBootstrap(ctx, id, resourceID, common.URL_SSH_KEY)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_ssh_key.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust SSH Key after creation",
			"Could not read SSH key "+resourceID+": "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "[resource_cm_ssh_key.go -> Create Output]["+fullResponse+"]")

	plan.ID = types.StringValue(gjson.Get(fullResponse, "id").String())
	plan.Name = types.StringValue(gjson.Get(fullResponse, "name").String())
	plan.Algorithm = types.StringValue(gjson.Get(fullResponse, "algorithm").String())
	plan.Fingerprint = types.StringValue(gjson.Get(fullResponse, "fingerprint").String())
	plan.CreatedAt = types.StringValue(gjson.Get(fullResponse, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(fullResponse, "updatedAt").String())

	// Unconditionally hydrate optional+computed fields in Create
	if r := gjson.Get(fullResponse, "size"); r.Exists() {
		plan.KeySize = types.Int64Value(r.Int())
	} else {
		plan.KeySize = types.Int64Null()
	}
	if r := gjson.Get(fullResponse, "curve"); r.Exists() {
		plan.Curve = types.StringValue(r.String())
	} else {
		plan.Curve = types.StringNull()
	}
	if r := gjson.Get(fullResponse, "username"); r.Exists() {
		plan.Username = types.StringValue(r.String())
	} else {
		plan.Username = types.StringNull()
	}
	if r := gjson.Get(fullResponse, "public_key_encoding"); r.Exists() {
		plan.PublicKeyEncoding = types.StringValue(r.String())
	} else {
		plan.PublicKeyEncoding = types.StringNull()
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_ssh_key.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMSSHKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_ssh_key.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_ssh_key.go -> Read]["+id+"]")

	var state CMSSHKeyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetByIdBootstrap(ctx, id, state.ID.ValueString(), common.URL_SSH_KEY)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_ssh_key.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust SSH Key",
			"Could not read SSH key "+state.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	// Computed-only — unconditional hydration (no r.Exists() guard per Check 8a)
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Algorithm = types.StringValue(gjson.Get(response, "algorithm").String())
	state.Fingerprint = types.StringValue(gjson.Get(response, "fingerprint").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	// Unconditionally hydrate optional+computed fields in Read to match Create
	if r := gjson.Get(response, "size"); r.Exists() {
		state.KeySize = types.Int64Value(r.Int())
	} else {
		state.KeySize = types.Int64Null()
	}
	if r := gjson.Get(response, "curve"); r.Exists() {
		state.Curve = types.StringValue(r.String())
	} else {
		state.Curve = types.StringNull()
	}
	if r := gjson.Get(response, "username"); r.Exists() {
		state.Username = types.StringValue(r.String())
	} else {
		state.Username = types.StringNull()
	}
	if r := gjson.Get(response, "public_key_encoding"); r.Exists() {
		state.PublicKeyEncoding = types.StringValue(r.String())
	} else {
		state.PublicKeyEncoding = types.StringNull()
	}

	// state.Key is write-only — CM never returns SSH key material in GET responses.
	// Preserved from prior state (no assignment).

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMSSHKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_ssh_key.go -> Update]")
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"ciphertrust_cm_ssh_key is a bootstrap-only resource and does not support updates. The SSH key cannot be modified after initial creation.",
	)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_ssh_key.go -> Update]")
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMSSHKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMSSHKeyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_ssh_key.go -> Delete]["+state.ID.ValueString()+"]")
	resp.Diagnostics.AddWarning(
		"Resource not deleted from CipherTrust Manager",
		"The CipherTrust API does not support deleting SSH keys. The key will be removed from the Terraform state, but it will remain on the server.",
	)
}

func (d *resourceCMSSHKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(common.CMClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected common.CMClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

func computeSSHFingerprint(pubKeyStr string) (string, error) {
	parts := strings.Fields(strings.TrimSpace(pubKeyStr))
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid SSH public key format")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 key material: %v", err)
	}

	hasher := sha256.New()
	hasher.Write(keyBytes)
	hash := hasher.Sum(nil)

	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return "SHA256:" + b64Hash, nil
}
