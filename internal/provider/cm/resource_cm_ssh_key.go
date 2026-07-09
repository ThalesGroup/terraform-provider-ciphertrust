package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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
	client *common.CMClientBootstrap
}

func (r *resourceCMSSHKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_ssh_key"
}

// Schema defines the schema for the resource.
func (r *resourceCMSSHKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Adds an SSH public key to the CipherTrust Manager appliance during initial bootstrap (provider `bootstrap = \"yes\"`). **Bootstrap mode is only available on CipherTrust Manager — this resource is implicitly unsupported on CDSPaaS.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) SSH public key to add to the CipherTrust Manager appliance during initial bootstrap.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"name": schema.StringAttribute{
				Computed: true,
			},
			"algorithm": schema.StringAttribute{
				Computed: true,
			},
			"key_size": schema.Int64Attribute{
				Optional: true,
				Computed: true,
			},
			"curve": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"username": schema.StringAttribute{
				Optional: true,
			},
			"public_key_encoding": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"fingerprint": schema.StringAttribute{
				Computed: true,
			},
			"created_at": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_at": schema.StringAttribute{
				Computed: true,
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

	response, err := r.client.PostDataBootstrap(ctx, id, common.URL_SSH_KEY, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_ssh_key.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating SSH Key on CipherTrust Manager: ",
			"Could not create SSH Key, unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "[resource_cm_ssh_key.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_ssh_key.go -> Create]["+id+"]")
	plan.ID = types.StringValue(response)
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

	// Optional+Computed and Optional fields — guard on !state.X.IsNull()
	if !state.KeySize.IsNull() {
		if r := gjson.Get(response, "size"); r.Exists() {
			state.KeySize = types.Int64Value(r.Int())
		} else {
			state.KeySize = types.Int64Null()
		}
	}
	if !state.Curve.IsNull() {
		if r := gjson.Get(response, "curve"); r.Exists() {
			state.Curve = types.StringValue(r.String())
		} else {
			state.Curve = types.StringNull()
		}
	}
	if !state.Username.IsNull() {
		if r := gjson.Get(response, "username"); r.Exists() {
			state.Username = types.StringValue(r.String())
		} else {
			state.Username = types.StringNull()
		}
	}
	if !state.PublicKeyEncoding.IsNull() {
		if r := gjson.Get(response, "public_key_encoding"); r.Exists() {
			state.PublicKeyEncoding = types.StringValue(r.String())
		} else {
			state.PublicKeyEncoding = types.StringNull()
		}
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

	client, ok := req.ProviderData.(*common.CMClientBootstrap)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}
