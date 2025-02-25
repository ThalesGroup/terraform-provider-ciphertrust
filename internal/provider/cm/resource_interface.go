package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCMInterface{}
	_ resource.ResourceWithConfigure = &resourceCMInterface{}
)

func NewResourceCMInterface() resource.Resource {
	return &resourceCMInterface{}
}

type resourceCMInterface struct {
	client *common.Client
}

func (r *resourceCMInterface) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_interface"
}

// Schema defines the schema for the resource.
func (r *resourceCMInterface) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"port": schema.Int64Attribute{
				Required:    true,
				Description: "The new interface will listen on the specified port. The port number should not be negative, 0 or the one already in-use.",
			},
			"allow_unregistered": schema.BoolAttribute{
				Optional:    true,
				Description: "If true, this flag enables interfaces to allow unregistered clients. only supported in NAE interface.",
			},
			"auto_gen_ca_id": schema.StringAttribute{
				Optional:    true,
				Description: "Auto-generate a new server certificate on server startup using the identifier (URI) of a Local CA resource if the current server certificate is issued by a different Local CA. This is especially useful when a new node joins the cluster. In this case, the existing data of the joining node is overwritten by the data in the cluster. A new server certificate is generated on the joining node using the existing Local CA of the cluster. Auto-generation of the server certificate can be disabled by setting auto_gen_ca_id to an empty string (\"\") to allow full control over the server certificate.",
			},
			"auto_gen_days_before_expiry": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of days before the server certificate expiry. When specified number of days are left in the expiry of the server certificate, the server certificate gets auto-generated and is made available as Upcoming Server Certificate on the interface.",
			},
			"auto_registration": schema.BoolAttribute{
				Optional:    true,
				Description: "Set auto registration to allow auto registration of kmip and nae clients.",
			},
			"cert_user_field": schema.StringAttribute{
				Optional:    true,
				Description: "Specifies how the user name is extracted from the client certificate. Allowed values are: CN, SN, E, E_ND, UID and OU. Refer to the top level discussion of the Interfaces section for more details.",
			},
			"custom_uid_size": schema.Int64Attribute{
				Optional:    true,
				Description: "This flag is used to define the custom uid size of managed object over the KMIP interface.",
			},
			"custom_uid_v2": schema.BoolAttribute{
				Optional:    true,
				Description: "This flag specifies which version of custom uid feature is to be used for KMIP interface. If it is set to true, new implementation i.e. Custom uid version 2 will be used.",
			},
			"default_connection": schema.StringAttribute{
				Optional:    true,
				Description: "The default connection may be \"local_account\" for local authentication or the LDAP domain for LDAP authentication. This value is applied when the username does not embed the connection name (e.g. \"jdoe\" effectively becomes \"local_account|jdoe\"). This value only applies to NAE only and is ignored if set for web and KMIP interfaces.",
			},
			"interface_type": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter is used to identify the type of interface, what service to run on the interface.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"web",
						"kmip",
						"nae",
						"snmp"}...),
				},
			},
			"kmip_enable_hard_delete": schema.Int64Attribute{
				Optional:    true,
				Description: "Enables hard delete of keys on KMIP Destroy operation, that is both meta-data and material will be removed from CipherTrust Manager for the key being deleted. By default, only key material is removed and meta-data is preserved with the updated key state. This setting applies only to KMIP interface. Should be set to 1 for enabling the feature or 0 for returning to default behavior.",
			},
			"maximum_tls_version": schema.StringAttribute{
				Optional:    true,
				Description: "Maximum TLS version to be configured for NAE or KMIP interface, default is latest maximum supported protocol.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"tls_1_0",
						"tls_1_1",
						"tls_1_2",
						"tls_1_3"}...),
				},
			},
			"meta": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Information which is used to create a Key using HKDF.",
				Attributes: map[string]schema.Attribute{
					"nae": schema.SingleNestedAttribute{
						Optional: true,
						Attributes: map[string]schema.Attribute{
							"mask_system_groups": schema.BoolAttribute{
								Optional: true,
							},
						},
					},
				},
			},
			"minimum_tls_version": schema.StringAttribute{
				Optional:    true,
				Description: "Minimum TLS version to be configured for NAE or KMIP interface, default is v1.2 (tls_1_2).",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"tls_1_0",
						"tls_1_1",
						"tls_1_2",
						"tls_1_3"}...),
				},
			},
			"mode": schema.StringAttribute{
				Optional:    true,
				Description: "The interface mode can be one of the following: no-tls-pw-opt, no-tls-pw-req, unauth-tls-pw-opt, tls-cert-opt-pw-opt, tls-pw-opt, tls-pw-req, tls-cert-pw-opt, or tls-cert-and-pw. Default mode is no-tls-pw-opt. Refer to the top level discussion of the Interface section for further details.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"no-tls-pw-opt",
						"no-tls-pw-req",
						"unauth-tls-pw-opt",
						"tls-cert-opt-pw-opt",
						"tls-pw-opt",
						"tls-pw-req",
						"tls-cert-pw-opt",
						"tls-cert-and-pw"}...),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "The name of the interface. Not valid for interface_type nae.",
			},
			"network_interface": schema.StringAttribute{
				Optional:    true,
				Description: "Defines what ethernet adapter the interface should listen to, use \"all\" for all. Defaults to all if not specified.",
			},
			"registration_token": schema.StringAttribute{
				Optional:    true,
				Description: "Registration token in case auto registration is true.",
			},
			"trusted_cas": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Information which is used to create a Key using HKDF.",
				Attributes: map[string]schema.Attribute{
					"external": schema.ListAttribute{
						Required:    true,
						Description: "A list of External CA IDs",
						ElementType: types.StringType,
					},
					"local": schema.ListAttribute{
						Required:    true,
						Description: "A list of Local CA IDs",
						ElementType: types.StringType,
					},
				},
			},
			"certificate": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Certificate to be associated with the interface",
				Attributes: map[string]schema.Attribute{
					"certificate_chain": schema.StringAttribute{
						Optional:    true,
						Description: "The certificate and key data in PEM format or base64 encoded PKCS12 format. A chain chain of certs may be included - it must be in ascending order (server to root ca).",
					},
					"generate": schema.BoolAttribute{
						Optional:    true,
						Description: "Create a new self-signed certificate.",
					},
					"format": schema.StringAttribute{
						Optional:    true,
						Description: "The format of the certificate data (PEM or PKCS12).",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"PKCS12",
								"PEM"}...),
						},
					},
					"password": schema.StringAttribute{
						Optional:    true,
						Description: "Password to the encrypted key.",
					},
				},
			},
			"local_auto_gen_attributes": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Local CSR parameters for interface's certificate. These are for the local node itself, and they do not affect other nodes in the cluster. This gives user a convenient way to supply custom fields for automatic interface certification generation. Without them, the system defaults are used.",
				Attributes: map[string]schema.Attribute{
					"cn": schema.StringAttribute{
						Optional: true,
					},
					"dns_names": schema.ListAttribute{
						Required:    true,
						ElementType: types.StringType,
					},
					"email_addresses": schema.ListAttribute{
						Required:    true,
						ElementType: types.StringType,
					},
					"ip_addresses": schema.ListAttribute{
						Required:    true,
						ElementType: types.StringType,
					},
					"names": schema.ListNestedAttribute{
						Optional:    true,
						Description: "Name fields are \"O=organization, OU=organizational unit, L=location, ST=state/province, C=country\"",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"c": schema.StringAttribute{
									Optional: true,
								},
								"l": schema.StringAttribute{
									Optional: true,
								},
								"o": schema.StringAttribute{
									Optional: true,
								},
								"ou": schema.StringAttribute{
									Optional: true,
								},
								"st": schema.StringAttribute{
									Optional: true,
								},
							},
						},
					},
					"uid": schema.StringAttribute{
						Optional: true,
					},
				},
			},
			"tls_ciphers": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Certificate to be associated with the interface",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"cipher_suite": schema.StringAttribute{
							Optional: true,
						},
						"enabled": schema.BoolAttribute{
							Optional: true,
						},
					},
				},
			},
			"created_at": schema.StringAttribute{
				Computed: true,
			},
			"updated_at": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMInterface) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_interface.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMInterfaceTFSDK
	var payload CMInterfaceJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Port = plan.Port.ValueInt64()
	if plan.AllowUnregistered.ValueBool() != types.BoolNull().ValueBool() {
		payload.AllowUnregistered = plan.AllowUnregistered.ValueBool()
	}
	if plan.AutogenCAId.ValueString() != "" && plan.AutogenCAId.ValueString() != types.StringNull().ValueString() {
		payload.AutogenCAId = plan.AutogenCAId.ValueString()
	}
	if plan.AutogenDaysBeforeExpiry.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.AutogenDaysBeforeExpiry = plan.AutogenDaysBeforeExpiry.ValueInt64()
	}
	if plan.AutoRegistration.ValueBool() != types.BoolNull().ValueBool() {
		payload.AutoRegistration = plan.AutoRegistration.ValueBool()
	}
	if plan.CertUserField.ValueString() != "" && plan.CertUserField.ValueString() != types.StringNull().ValueString() {
		payload.CertUserField = plan.CertUserField.ValueString()
	}
	if plan.CustomUIDSize.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.CustomUIDSize = plan.CustomUIDSize.ValueInt64()
	}
	if plan.CustomUIDv2.ValueBool() != types.BoolNull().ValueBool() {
		payload.CustomUIDv2 = plan.CustomUIDv2.ValueBool()
	}
	if plan.DefaultConnection.ValueString() != "" && plan.DefaultConnection.ValueString() != types.StringNull().ValueString() {
		payload.DefaultConnection = plan.DefaultConnection.ValueString()
	}
	if plan.InterfaceType.ValueString() != "" && plan.InterfaceType.ValueString() != types.StringNull().ValueString() {
		payload.InterfaceType = plan.InterfaceType.ValueString()
	}
	if plan.KMIPEnableHardDelete.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.KMIPEnableHardDelete = plan.KMIPEnableHardDelete.ValueInt64()
	}
	if plan.MaximumTLSVersion.ValueString() != "" && plan.MaximumTLSVersion.ValueString() != types.StringNull().ValueString() {
		payload.MaximumTLSVersion = plan.MaximumTLSVersion.ValueString()
	}
	var metadata CMInterfaceMetadataJSON
	var metadataNAE CMInterfaceMetadataNAEJSON
	if !reflect.DeepEqual((*CMInterfaceMetadataTFSDK)(nil), plan.Meta) {
		tflog.Debug(ctx, "Metadata should not be empty at this point")
		if !reflect.DeepEqual((*CMInterfaceMetadataNAETFSDK)(nil), plan.Meta.NAE) {
			if plan.Meta.NAE.MaskSystemGroups.ValueBool() != types.BoolNull().ValueBool() {
				metadataNAE.MaskSystemGroups = plan.Meta.NAE.MaskSystemGroups.ValueBool()
				metadata.NAE = metadataNAE
			}
		}
		payload.Meta = metadata
	}
	if plan.MinimumTLSVersion.ValueString() != "" && plan.MinimumTLSVersion.ValueString() != types.StringNull().ValueString() {
		payload.MinimumTLSVersion = plan.MinimumTLSVersion.ValueString()
	}
	if plan.Mode.ValueString() != "" && plan.Mode.ValueString() != types.StringNull().ValueString() {
		payload.Mode = plan.Mode.ValueString()
	}
	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}
	if plan.NetworkInterface.ValueString() != "" && plan.NetworkInterface.ValueString() != types.StringNull().ValueString() {
		payload.NetworkInterface = plan.NetworkInterface.ValueString()
	}
	if plan.RegToken.ValueString() != "" && plan.RegToken.ValueString() != types.StringNull().ValueString() {
		payload.RegToken = plan.RegToken.ValueString()
	}
	var trustedCAs CMInterfacTrustedCAsJSON
	if !reflect.DeepEqual((*CMInterfacTrustedCAsTFSDK)(nil), plan.TrustedCAs) {
		tflog.Debug(ctx, "Trusted CAs should not be empty at this point")
		if len(plan.TrustedCAs.External) > 0 {
			var externalCAs []string
			for _, str := range plan.TrustedCAs.External {
				externalCAs = append(externalCAs, str.ValueString())
			}
			trustedCAs.External = externalCAs
		}
		if len(plan.TrustedCAs.Local) > 0 {
			var localCAs []string
			for _, str := range plan.TrustedCAs.Local {
				localCAs = append(localCAs, str.ValueString())
			}
			trustedCAs.Local = localCAs
		}
		payload.TrustedCAs = trustedCAs
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_interface.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Interface Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_DOMAIN, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_interface.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating Interface on CipherTrust Manager: ",
			"Could not create Interface, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.Name = types.StringValue(gjson.Get(response, "name").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	tflog.Debug(ctx, "[resource_interface.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_interface.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMInterface) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMInterfaceTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.Name.ValueString(), common.URL_DOMAIN)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_interface.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CM interface on CipherTrust Manager: ",
			"Could not read CM interface id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.Mode = types.StringValue(gjson.Get(response, "mode").String())
	state.CertUserField = types.StringValue(gjson.Get(response, "cert_user_field").String())
	state.AutogenCAId = types.StringValue(gjson.Get(response, "auto_gen_ca_id").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_interface.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMInterface) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	var plan CMInterfaceTFSDK
	var payload CMInterfaceJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.AllowUnregistered.ValueBool() != types.BoolNull().ValueBool() {
		payload.AllowUnregistered = plan.AllowUnregistered.ValueBool()
	}
	if plan.AutogenCAId.ValueString() != "" && plan.AutogenCAId.ValueString() != types.StringNull().ValueString() {
		payload.AutogenCAId = plan.AutogenCAId.ValueString()
	}
	if plan.AutogenDaysBeforeExpiry.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.AutogenDaysBeforeExpiry = plan.AutogenDaysBeforeExpiry.ValueInt64()
	}
	if plan.AutoRegistration.ValueBool() != types.BoolNull().ValueBool() {
		payload.AutoRegistration = plan.AutoRegistration.ValueBool()
	}
	if plan.CertUserField.ValueString() != "" && plan.CertUserField.ValueString() != types.StringNull().ValueString() {
		payload.CertUserField = plan.CertUserField.ValueString()
	}
	if plan.CustomUIDSize.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.CustomUIDSize = plan.CustomUIDSize.ValueInt64()
	}
	if plan.CustomUIDv2.ValueBool() != types.BoolNull().ValueBool() {
		payload.CustomUIDv2 = plan.CustomUIDv2.ValueBool()
	}
	if plan.DefaultConnection.ValueString() != "" && plan.DefaultConnection.ValueString() != types.StringNull().ValueString() {
		payload.DefaultConnection = plan.DefaultConnection.ValueString()
	}
	if plan.KMIPEnableHardDelete.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.KMIPEnableHardDelete = plan.KMIPEnableHardDelete.ValueInt64()
	}
	var attributes CMInterfaceLocalAutogenAttrJSON
	if !reflect.DeepEqual((*CMInterfaceLocalAutogenAttrTFSDK)(nil), plan.LocalAutogenAttributes) {
		tflog.Debug(ctx, "local_auto_gen_attributes should not be empty at this point")
		if plan.LocalAutogenAttributes.CN.ValueString() != "" && plan.LocalAutogenAttributes.CN.ValueString() != types.StringNull().ValueString() {
			attributes.CN = plan.LocalAutogenAttributes.CN.ValueString()
		}

		var dns_arr []string
		for _, str := range plan.LocalAutogenAttributes.DNSNames {
			dns_arr = append(dns_arr, str.ValueString())
		}
		attributes.DNSNames = dns_arr

		var emails_arr []string
		for _, str := range plan.LocalAutogenAttributes.Emails {
			emails_arr = append(emails_arr, str.ValueString())
		}
		attributes.Emails = emails_arr

		var ip_arr []string
		for _, str := range plan.LocalAutogenAttributes.IPAddresses {
			ip_arr = append(ip_arr, str.ValueString())
		}
		attributes.IPAddresses = ip_arr

		var names_arr []NamesParamsJSON
		for _, nameInput := range plan.LocalAutogenAttributes.Names {
			var name NamesParamsJSON
			name.C = nameInput.C.ValueString()
			name.L = nameInput.L.ValueString()
			name.O = nameInput.O.ValueString()
			name.OU = nameInput.OU.ValueString()
			name.ST = nameInput.ST.ValueString()
			names_arr = append(names_arr, name)
		}
		attributes.Names = names_arr

		if plan.LocalAutogenAttributes.UID.ValueString() != "" && plan.LocalAutogenAttributes.UID.ValueString() != types.StringNull().ValueString() {
			attributes.UID = plan.LocalAutogenAttributes.UID.ValueString()
		}

		payload.LocalAutogenAttributes = attributes
	}

	if plan.MaximumTLSVersion.ValueString() != "" && plan.MaximumTLSVersion.ValueString() != types.StringNull().ValueString() {
		payload.MaximumTLSVersion = plan.MaximumTLSVersion.ValueString()
	}
	var metadata CMInterfaceMetadataJSON
	var metadataNAE CMInterfaceMetadataNAEJSON
	if !reflect.DeepEqual((*CMInterfaceMetadataTFSDK)(nil), plan.Meta) {
		tflog.Debug(ctx, "Metadata should not be empty at this point")
		if !reflect.DeepEqual((*CMInterfaceMetadataNAETFSDK)(nil), plan.Meta.NAE) {
			if plan.Meta.NAE.MaskSystemGroups.ValueBool() != types.BoolNull().ValueBool() {
				metadataNAE.MaskSystemGroups = plan.Meta.NAE.MaskSystemGroups.ValueBool()
				metadata.NAE = metadataNAE
			}
		}
		payload.Meta = metadata
	}
	if plan.MinimumTLSVersion.ValueString() != "" && plan.MinimumTLSVersion.ValueString() != types.StringNull().ValueString() {
		payload.MinimumTLSVersion = plan.MinimumTLSVersion.ValueString()
	}
	if plan.Mode.ValueString() != "" && plan.Mode.ValueString() != types.StringNull().ValueString() {
		payload.Mode = plan.Mode.ValueString()
	}
	if plan.NetworkInterface.ValueString() != "" && plan.NetworkInterface.ValueString() != types.StringNull().ValueString() {
		payload.NetworkInterface = plan.NetworkInterface.ValueString()
	}
	if plan.Port.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.Port = plan.Port.ValueInt64()
	}
	if plan.RegToken.ValueString() != "" && plan.RegToken.ValueString() != types.StringNull().ValueString() {
		payload.RegToken = plan.RegToken.ValueString()
	}

	if len(plan.TLSCiphers) > 0 {
		var ciphers []TLSCiphersJSON
		for _, cipherInput := range plan.TLSCiphers {
			var cipher TLSCiphersJSON
			if cipherInput.CipherSuite.ValueString() != "" && cipherInput.CipherSuite.ValueString() != types.StringNull().ValueString() {
				cipher.CipherSuite = cipherInput.CipherSuite.ValueString()
			}
			if cipherInput.Enabled.ValueBool() != types.BoolNull().ValueBool() {
				cipher.Enabled = cipherInput.Enabled.ValueBool()
			}
			ciphers = append(ciphers, cipher)
		}
		payload.TLSCiphers = ciphers
	}

	var trustedCAs CMInterfacTrustedCAsJSON
	if !reflect.DeepEqual((*CMInterfacTrustedCAsTFSDK)(nil), plan.TrustedCAs) {
		tflog.Debug(ctx, "Trusted CAs should not be empty at this point")
		if len(plan.TrustedCAs.External) > 0 {
			var externalCAs []string
			for _, str := range plan.TrustedCAs.External {
				externalCAs = append(externalCAs, str.ValueString())
			}
			trustedCAs.External = externalCAs
		}
		if len(plan.TrustedCAs.Local) > 0 {
			var localCAs []string
			for _, str := range plan.TrustedCAs.Local {
				localCAs = append(localCAs, str.ValueString())
			}
			trustedCAs.Local = localCAs
		}
		payload.TrustedCAs = trustedCAs
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_interface.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: interface Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.Name.ValueString(), common.URL_DOMAIN, payloadJSON, "updatedAt")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_interface.go -> Update]["+plan.Name.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating interface on CipherTrust Manager: ",
			"Could not update interface, unexpected error: "+err.Error(),
		)
		return
	}
	plan.UpdatedAt = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMInterface) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMInterfaceTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_INTERFACE, state.Name.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.Name.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_interface.go -> Delete]["+state.Name.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust interface",
			"Could not delete interface, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMInterface) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	d.client = client
}
