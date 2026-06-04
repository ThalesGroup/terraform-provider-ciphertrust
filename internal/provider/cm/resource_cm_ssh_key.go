package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
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
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key": schema.StringAttribute{
				Required: true,
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
//
// The SSH key is managed with the bootstrap client, so it is fetched via
// GetByIdBootstrap. On a 404 the key is removed from state so a subsequent plan
// recreates it. The public key material is generally returned by the API; if
// the response omits it, the prior state value is retained to avoid a spurious
// replacement.
func (r *resourceCMSSHKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_cm_ssh_key.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_cm_ssh_key.go -> Read]["+id+"]")

	var state CMSSHKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetByIdBootstrap(ctx, id, state.ID.ValueString(), common.URL_SSH_KEY)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			tflog.Warn(ctx, "[resource_cm_ssh_key.go -> Read][ssh key not found, removing from state][id: "+state.ID.ValueString()+"]")
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_ssh_key.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust SSH Key",
			"Could not read CipherTrust SSH key ID "+state.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	var sshKey CMSSHKeyJSON
	if err := json.Unmarshal([]byte(response), &sshKey); err != nil {
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust SSH Key",
			"Could not parse CipherTrust SSH key response: "+err.Error(),
		)
		return
	}

	// Preserve the prior public key when the API does not return it.
	if sshKey.Key != "" {
		state.Key = types.StringValue(sshKey.Key)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMSSHKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
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
