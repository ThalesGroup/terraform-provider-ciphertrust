package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &resourceCMInterface{}
	_ resource.ResourceWithConfigure      = &resourceCMInterface{}
	_ resource.ResourceWithValidateConfig = &resourceCMInterface{}
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

func (r *resourceCMInterface) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_interface", resp)
}

// Schema defines the schema for the resource.
func (r *resourceCMInterface) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a service endpoint interface (NAE, KMIP, or SNMP) on the CipherTrust Manager appliance, controlling the port, TLS settings, authentication mode, and network binding. **Only available on CipherTrust Manager — not supported on CDSPaaS.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique identifier of the interface.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"port": schema.Int64Attribute{
				Required:    true,
				Description: "(Immutable) The new interface will listen on the specified port. The port number should not be negative, 0 or the one already in-use.",
				PlanModifiers: []planmodifier.Int64{
					modifiers.ImmutableInt64(),
				},
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
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"CN",
						"SN",
						"E",
						"E_ND",
						"UID",
						"OU"}...),
				},
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
				Computed:    true,
				Description: "(Immutable) This parameter is used to identify the type of interface, what service to run on the interface.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"web",
						"kmip",
						"nae",
						"snmp"}...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableString(),
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
				Description: "Meta information related to the interface.",
				Attributes: map[string]schema.Attribute{
					"nae": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Meta information related to the NAE interface.",
						Attributes: map[string]schema.Attribute{
							"mask_system_groups": schema.BoolAttribute{
								Optional:    true,
								Description: "Flag for masking system groups in NAE requests.",
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
				Computed:    true,
				Description: "(Immutable) The name of the interface. Not valid for interface_type nae or kmip — CM auto-assigns the name for those types.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableString(),
				},
			},
			"network_interface": schema.StringAttribute{
				Optional:    true,
				Description: "Defines what ethernet adapter the interface should listen to, use \"all\" for all. Defaults to all if not specified.",
			},
			"registration_token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Registration token in case auto registration is true.",
			},
			"trusted_cas": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Collection of local and external CA IDs to trust for client authentication on this interface.",
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
						Sensitive:   true,
						Description: "Password to the encrypted key.",
					},
				},
			},
			"local_auto_gen_attributes": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Local CSR parameters for interface's certificate. These are for the local node itself, and they do not affect other nodes in the cluster. This gives user a convenient way to supply custom fields for automatic interface certification generation. Without them, the system defaults are used.",
				Attributes: map[string]schema.Attribute{
					"cn": schema.StringAttribute{
						Optional:    true,
						Description: "Common Name (CN) to use for the interface's auto-generated certificate/CSR.",
					},
					"dns_names": schema.ListAttribute{
						Required:    true,
						Description: "Subject Alternative Name (SAN) DNS names for the interface's auto-generated certificate/CSR.",
						ElementType: types.StringType,
					},
					"email_addresses": schema.ListAttribute{
						Required:    true,
						Description: "Subject Alternative Name (SAN) email addresses for the interface's auto-generated certificate/CSR.",
						ElementType: types.StringType,
					},
					"ip_addresses": schema.ListAttribute{
						Required:    true,
						Description: "Subject Alternative Name (SAN) IP addresses for the interface's auto-generated certificate/CSR.",
						ElementType: types.StringType,
					},
					"names": schema.ListNestedAttribute{
						Optional:    true,
						Description: "Name fields are \"O=organization, OU=organizational unit, L=location, ST=state/province, C=country\"",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"c": schema.StringAttribute{
									Optional:    true,
									Description: "Country, for example \"US\".",
								},
								"l": schema.StringAttribute{
									Optional:    true,
									Description: "Locality, for example \"Belcamp\".",
								},
								"o": schema.StringAttribute{
									Optional:    true,
									Description: "Organization, for example \"Thales Group\".",
								},
								"ou": schema.StringAttribute{
									Optional:    true,
									Description: "Organizational Unit, for example \"Accounting\".",
								},
								"st": schema.StringAttribute{
									Optional:    true,
									Description: "State/province, for example \"MD\".",
								},
							},
						},
					},
					"uid": schema.StringAttribute{
						Optional:    true,
						Description: "Subject UID to use for the interface's auto-generated certificate/CSR.",
					},
				},
			},
			"tls_ciphers": schema.ListNestedAttribute{
				Optional:    true,
				Description: "The list of TLS cipher suites available for the interface's (KMIP, NAE, or Web) TLS handshake, and whether each is enabled.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"cipher_suite": schema.StringAttribute{
							Optional:    true,
							Description: "TLS cipher suite name.",
						},
						"enabled": schema.BoolAttribute{
							Optional:    true,
							Description: "TLS cipher suite enabled flag. If set to true, the cipher suite will be available for the TLS handshake.",
						},
					},
				},
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the interface was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the interface was last updated.",
				// No UseStateForUnknown — CM writes a new timestamp on every PATCH.
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMInterface) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_interface.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan CMInterfaceTFSDK
	var payload CMInterfaceJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Port = plan.Port.ValueInt64()
	if !plan.AllowUnregistered.IsNull() && !plan.AllowUnregistered.IsUnknown() {
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
		r.client.Log.Debug("Metadata should not be empty at this point")
		if !reflect.DeepEqual((*CMInterfaceMetadataNAETFSDK)(nil), plan.Meta.NAE) {
			if plan.Meta.NAE.MaskSystemGroups.ValueBool() != types.BoolNull().ValueBool() {
				metadataNAE.MaskSystemGroups = plan.Meta.NAE.MaskSystemGroups.ValueBool()
				metadata.NAE = metadataNAE
			}
		}
		payload.Meta = &metadata
	}
	if plan.MinimumTLSVersion.ValueString() != "" && plan.MinimumTLSVersion.ValueString() != types.StringNull().ValueString() {
		payload.MinimumTLSVersion = plan.MinimumTLSVersion.ValueString()
	}
	if plan.Mode.ValueString() != "" && plan.Mode.ValueString() != types.StringNull().ValueString() {
		payload.Mode = plan.Mode.ValueString()
	}
	// CM rejects an explicit name on create for nae and kmip interfaces
	// ("Name is not allowed while creating KMIP interface") — it auto-assigns
	// one instead. Only forward a user-supplied name for interface types that
	// accept it (web, snmp).
	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() &&
		plan.InterfaceType.ValueString() != "nae" && plan.InterfaceType.ValueString() != "kmip" {
		payload.Name = plan.Name.ValueString()
	}
	if plan.NetworkInterface.ValueString() != "" && plan.NetworkInterface.ValueString() != types.StringNull().ValueString() {
		payload.NetworkInterface = plan.NetworkInterface.ValueString()
	}
	if plan.RegToken.ValueString() != "" && plan.RegToken.ValueString() != types.StringNull().ValueString() {
		payload.RegToken = plan.RegToken.ValueString()
	}
	if !reflect.DeepEqual((*CMInterfacTrustedCAsTFSDK)(nil), plan.TrustedCAs) {
		r.client.Log.Debug("Trusted CAs should not be empty at this point")
		var trustedCAs CMInterfacTrustedCAsJSON
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
		payload.TrustedCAs = &trustedCAs
	}

	// local_auto_gen_attributes (TFIN-534): Create() previously omitted this block entirely.
	// Update() had the correct logic; copy it here so the first apply converges without
	// requiring a redundant second apply.
	if plan.LocalAutogenAttributes != nil {
		var attributes CMInterfaceLocalAutogenAttrJSON
		if plan.LocalAutogenAttributes.CN.ValueString() != "" && plan.LocalAutogenAttributes.CN.ValueString() != types.StringNull().ValueString() {
			attributes.CN = plan.LocalAutogenAttributes.CN.ValueString()
		}
		var dnsArr []string
		for _, s := range plan.LocalAutogenAttributes.DNSNames {
			dnsArr = append(dnsArr, s.ValueString())
		}
		attributes.DNSNames = dnsArr
		var emailsArr []string
		for _, s := range plan.LocalAutogenAttributes.Emails {
			emailsArr = append(emailsArr, s.ValueString())
		}
		attributes.Emails = emailsArr
		var ipArr []string
		for _, s := range plan.LocalAutogenAttributes.IPAddresses {
			ipArr = append(ipArr, s.ValueString())
		}
		attributes.IPAddresses = ipArr
		var namesArr []NamesParamsJSON
		for _, n := range plan.LocalAutogenAttributes.Names {
			namesArr = append(namesArr, NamesParamsJSON{
				C: n.C.ValueString(), L: n.L.ValueString(),
				O: n.O.ValueString(), OU: n.OU.ValueString(), ST: n.ST.ValueString(),
			})
		}
		attributes.Names = namesArr
		if plan.LocalAutogenAttributes.UID.ValueString() != "" && plan.LocalAutogenAttributes.UID.ValueString() != types.StringNull().ValueString() {
			attributes.UID = plan.LocalAutogenAttributes.UID.ValueString()
		}
		payload.LocalAutogenAttributes = &attributes
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_interface.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: Interface Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_INTERFACE, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_interface.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating Interface on CipherTrust Manager: ",
			"Could not create Interface, unexpected error: "+err.Error(),
		)
		return
	}

	// Computed-only — hydrate unconditionally.
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	// Required.
	plan.Port = types.Int64Value(gjson.Get(response, "port").Int())

	// Optional+Computed: hydrate unconditionally — framework allows server values for Computed fields.
	if r := gjson.Get(response, "name"); r.Exists() && r.String() != "" {
		plan.Name = types.StringValue(r.String())
	} else {
		plan.Name = types.StringNull()
	}
	if r := gjson.Get(response, "interface_type"); r.Exists() && r.String() != "" {
		plan.InterfaceType = types.StringValue(r.String())
	} else {
		plan.InterfaceType = types.StringNull()
	}

	// Optional scalars — only hydrate when the user configured the field (plan is non-null).
	// If the plan is null the API may return a server default; preserving null avoids the
	// "Provider produced inconsistent result after apply" framework error.
	if !plan.AllowUnregistered.IsNull() && !plan.AllowUnregistered.IsUnknown() {
		if r := gjson.Get(response, "allow_unregistered"); r.Exists() {
			plan.AllowUnregistered = types.BoolValue(r.Bool())
		} else {
			plan.AllowUnregistered = types.BoolNull()
		}
	}
	if !plan.AutogenCAId.IsNull() && !plan.AutogenCAId.IsUnknown() {
		if r := gjson.Get(response, "auto_gen_ca_id"); r.Exists() && r.String() != "" {
			plan.AutogenCAId = types.StringValue(r.String())
		} else {
			plan.AutogenCAId = types.StringNull()
		}
	}
	if !plan.AutogenDaysBeforeExpiry.IsNull() && !plan.AutogenDaysBeforeExpiry.IsUnknown() {
		if r := gjson.Get(response, "auto_gen_days_before_expiry"); r.Exists() {
			plan.AutogenDaysBeforeExpiry = types.Int64Value(r.Int())
		} else {
			plan.AutogenDaysBeforeExpiry = types.Int64Null()
		}
	}
	if !plan.AutoRegistration.IsNull() && !plan.AutoRegistration.IsUnknown() {
		if r := gjson.Get(response, "auto_registration"); r.Exists() {
			plan.AutoRegistration = types.BoolValue(r.Bool())
		}
		// else: CM omits auto_registration from create response (write-only field).
		// plan.AutoRegistration already holds the user's configured value — preserve it.
	}
	if !plan.CertUserField.IsNull() && !plan.CertUserField.IsUnknown() {
		if r := gjson.Get(response, "cert_user_field"); r.Exists() && r.String() != "" {
			plan.CertUserField = types.StringValue(r.String())
		} else {
			plan.CertUserField = types.StringNull()
		}
	}
	if !plan.CustomUIDSize.IsNull() && !plan.CustomUIDSize.IsUnknown() {
		if r := gjson.Get(response, "custom_uid_size"); r.Exists() {
			plan.CustomUIDSize = types.Int64Value(r.Int())
		} else {
			plan.CustomUIDSize = types.Int64Null()
		}
	}
	if !plan.CustomUIDv2.IsNull() && !plan.CustomUIDv2.IsUnknown() {
		if r := gjson.Get(response, "custom_uid_v2"); r.Exists() {
			plan.CustomUIDv2 = types.BoolValue(r.Bool())
		} else {
			plan.CustomUIDv2 = types.BoolNull()
		}
	}
	if !plan.DefaultConnection.IsNull() && !plan.DefaultConnection.IsUnknown() {
		if r := gjson.Get(response, "default_connection"); r.Exists() && r.String() != "" {
			plan.DefaultConnection = types.StringValue(r.String())
		} else {
			plan.DefaultConnection = types.StringNull()
		}
	}
	if !plan.KMIPEnableHardDelete.IsNull() && !plan.KMIPEnableHardDelete.IsUnknown() {
		if r := gjson.Get(response, "kmip_enable_hard_delete"); r.Exists() {
			plan.KMIPEnableHardDelete = types.Int64Value(r.Int())
		} else {
			plan.KMIPEnableHardDelete = types.Int64Null()
		}
	}
	if !plan.MaximumTLSVersion.IsNull() && !plan.MaximumTLSVersion.IsUnknown() {
		if r := gjson.Get(response, "maximum_tls_version"); r.Exists() && r.String() != "" {
			plan.MaximumTLSVersion = types.StringValue(r.String())
		} else {
			plan.MaximumTLSVersion = types.StringNull()
		}
	}
	if !plan.MinimumTLSVersion.IsNull() && !plan.MinimumTLSVersion.IsUnknown() {
		if r := gjson.Get(response, "minimum_tls_version"); r.Exists() && r.String() != "" {
			plan.MinimumTLSVersion = types.StringValue(r.String())
		} else {
			plan.MinimumTLSVersion = types.StringNull()
		}
	}
	if !plan.Mode.IsNull() && !plan.Mode.IsUnknown() {
		if r := gjson.Get(response, "mode"); r.Exists() && r.String() != "" {
			plan.Mode = types.StringValue(r.String())
		} else {
			plan.Mode = types.StringNull()
		}
	}
	if !plan.NetworkInterface.IsNull() && !plan.NetworkInterface.IsUnknown() {
		if r := gjson.Get(response, "network_interface"); r.Exists() && r.String() != "" {
			plan.NetworkInterface = types.StringValue(r.String())
		} else {
			plan.NetworkInterface = types.StringNull()
		}
	}

	// tls_ciphers — only hydrate when the user configured it; server always returns defaults.
	if plan.TLSCiphers != nil {
		if ciphersResult := gjson.Get(response, "tls_ciphers"); ciphersResult.Exists() {
			var ciphers []TLSCiphersTFSDK
			for _, c := range ciphersResult.Array() {
				ciphers = append(ciphers, TLSCiphersTFSDK{
					CipherSuite: types.StringValue(c.Get("cipher_suite").String()),
					Enabled:     types.BoolValue(c.Get("enabled").Bool()),
				})
			}
			plan.TLSCiphers = ciphers
		} else {
			plan.TLSCiphers = nil
		}
	}

	// registration_token — write-only; plan.RegToken already holds the user's configured value.
	// certificate — write-only; plan.Certificate already holds the user's configured value.

	r.client.Log.Debug("[resource_interface.go -> Create Output][" + response + "]")

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_interface.go -> Create][" + id + "]")
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
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_interface.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// CM interface API uses NAME (not UUID) as the path key — UUID lookup returns 404.
	// This is a documented exception to the general CM CRUD convention.
	response, err := r.client.ReadDataByParam(ctx, id, state.Name.ValueString(), common.URL_INTERFACE)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				"CM Interface Not Found — State Preserved",
				"The CM Interface resource was not found on CipherTrust Manager (HTTP 404). To prevent accidental data loss, this resource has been kept in state.",
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_interface.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading CM interface on CipherTrust Manager: ",
			"Could not read CM interface id: "+state.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	// Computed-only — hydrate unconditionally.
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	// Required.
	state.Port = types.Int64Value(gjson.Get(response, "port").Int())

	// Optional+Computed: hydrate unconditionally.
	if r := gjson.Get(response, "name"); r.Exists() && r.String() != "" {
		state.Name = types.StringValue(r.String())
	} else {
		state.Name = types.StringNull()
	}
	if r := gjson.Get(response, "interface_type"); r.Exists() && r.String() != "" {
		state.InterfaceType = types.StringValue(r.String())
	} else {
		state.InterfaceType = types.StringNull()
	}

	// Optional scalars — only hydrate when state already holds a non-null value.
	// For fields the user never set, preserve null to avoid perpetual server-default drift.
	if !state.AllowUnregistered.IsNull() {
		if r := gjson.Get(response, "allow_unregistered"); r.Exists() {
			state.AllowUnregistered = types.BoolValue(r.Bool())
		} else {
			state.AllowUnregistered = types.BoolNull()
		}
	}
	if !state.AutogenCAId.IsNull() {
		if r := gjson.Get(response, "auto_gen_ca_id"); r.Exists() && r.String() != "" {
			state.AutogenCAId = types.StringValue(r.String())
		} else {
			state.AutogenCAId = types.StringNull()
		}
	}
	if !state.AutogenDaysBeforeExpiry.IsNull() {
		if r := gjson.Get(response, "auto_gen_days_before_expiry"); r.Exists() {
			state.AutogenDaysBeforeExpiry = types.Int64Value(r.Int())
		} else {
			state.AutogenDaysBeforeExpiry = types.Int64Null()
		}
	}
	// auto_registration (Optional, write-only on create):
	// - CM returns true  → store true in state.
	// - CM returns false → field was cleared; null is the correct Terraform state.
	// - CM omits key     → preserve prior state (write-only create: key absent from 201 and
	//                      subsequent GET until the value is explicitly set/cleared).
	if r := gjson.Get(response, "auto_registration"); r.Exists() {
		if r.Bool() {
			state.AutoRegistration = types.BoolValue(true)
		} else if !state.AutoRegistration.IsNull() {
			state.AutoRegistration = types.BoolNull()
		}
	}
	// else: key absent — leave state.AutoRegistration unchanged.
	if !state.CertUserField.IsNull() {
		if r := gjson.Get(response, "cert_user_field"); r.Exists() && r.String() != "" {
			state.CertUserField = types.StringValue(r.String())
		} else {
			state.CertUserField = types.StringNull()
		}
	}
	if !state.CustomUIDSize.IsNull() {
		if r := gjson.Get(response, "custom_uid_size"); r.Exists() {
			state.CustomUIDSize = types.Int64Value(r.Int())
		} else {
			state.CustomUIDSize = types.Int64Null()
		}
	}
	if !state.CustomUIDv2.IsNull() {
		if r := gjson.Get(response, "custom_uid_v2"); r.Exists() {
			state.CustomUIDv2 = types.BoolValue(r.Bool())
		} else {
			state.CustomUIDv2 = types.BoolNull()
		}
	}
	if !state.DefaultConnection.IsNull() {
		if r := gjson.Get(response, "default_connection"); r.Exists() && r.String() != "" {
			state.DefaultConnection = types.StringValue(r.String())
		} else {
			state.DefaultConnection = types.StringNull()
		}
	}
	if !state.KMIPEnableHardDelete.IsNull() {
		if r := gjson.Get(response, "kmip_enable_hard_delete"); r.Exists() {
			state.KMIPEnableHardDelete = types.Int64Value(r.Int())
		} else {
			state.KMIPEnableHardDelete = types.Int64Null()
		}
	}
	if !state.MaximumTLSVersion.IsNull() {
		if r := gjson.Get(response, "maximum_tls_version"); r.Exists() && r.String() != "" {
			state.MaximumTLSVersion = types.StringValue(r.String())
		} else {
			state.MaximumTLSVersion = types.StringNull()
		}
	}
	if !state.MinimumTLSVersion.IsNull() {
		if r := gjson.Get(response, "minimum_tls_version"); r.Exists() && r.String() != "" {
			state.MinimumTLSVersion = types.StringValue(r.String())
		} else {
			state.MinimumTLSVersion = types.StringNull()
		}
	}
	if !state.Mode.IsNull() {
		if r := gjson.Get(response, "mode"); r.Exists() && r.String() != "" {
			state.Mode = types.StringValue(r.String())
		} else {
			state.Mode = types.StringNull()
		}
	}
	if !state.NetworkInterface.IsNull() {
		if r := gjson.Get(response, "network_interface"); r.Exists() && r.String() != "" {
			state.NetworkInterface = types.StringValue(r.String())
		} else {
			state.NetworkInterface = types.StringNull()
		}
	}

	// Nested: meta — only hydrate when user configured it (state non-nil).
	if state.Meta != nil {
		if metaResult := gjson.Get(response, "meta"); metaResult.Exists() && metaResult.Type != gjson.Null {
			naeResult := gjson.Get(response, "meta.nae")
			if naeResult.Exists() && naeResult.Type != gjson.Null {
				state.Meta = &CMInterfaceMetadataTFSDK{
					NAE: &CMInterfaceMetadataNAETFSDK{
						MaskSystemGroups: types.BoolValue(gjson.Get(response, "meta.nae.mask_system_groups").Bool()),
					},
				}
			} else {
				state.Meta = &CMInterfaceMetadataTFSDK{NAE: nil}
			}
		} else {
			state.Meta = nil
		}
	}

	// Nested: trusted_cas — only hydrate when user configured it (state non-nil).
	if state.TrustedCAs != nil {
		if tcResult := gjson.Get(response, "trusted_cas"); tcResult.Exists() && tcResult.Type != gjson.Null {
			extResult := gjson.Get(response, "trusted_cas.external")
			var ext []types.String
			if extResult.Exists() && extResult.IsArray() {
				for _, v := range extResult.Array() {
					ext = append(ext, types.StringValue(v.String()))
				}
			} else {
				// CM omits 'external' key when the list is empty (confirmed live: GET nae_all_9851
				// returned trusted_cas with only 'local' key). 'external' is Required within
				// trusted_cas — preserve prior state value to prevent perpetual drift.
				if state.TrustedCAs.External != nil {
					ext = state.TrustedCAs.External
				} else {
					ext = []types.String{}
				}
			}
			var loc []types.String
			for _, v := range gjson.Get(response, "trusted_cas.local").Array() {
				loc = append(loc, types.StringValue(v.String()))
			}
			state.TrustedCAs = &CMInterfacTrustedCAsTFSDK{External: ext, Local: loc}
		} else {
			state.TrustedCAs = nil
		}
	}

	// Nested: local_auto_gen_attributes — only hydrate when user configured it (state non-nil).
	// CM is expected to always return dns_names, email_addresses, and ip_addresses when the
	// local_auto_gen_attributes block is present in the response — these are Required sub-fields.
	// When a sub-field is absent (anomalous CM behaviour), the field is left at its zero value
	// (nil slice from struct initialisation) rather than explicitly assigned nil.
	if state.LocalAutogenAttributes != nil {
		if lagaResult := gjson.Get(response, "local_auto_gen_attributes"); lagaResult.Exists() && lagaResult.Type != gjson.Null {
			var laga CMInterfaceLocalAutogenAttrTFSDK
			if r := gjson.Get(response, "local_auto_gen_attributes.cn"); r.Exists() && r.String() != "" {
				laga.CN = types.StringValue(r.String())
			} else {
				laga.CN = types.StringNull()
			}
			// dns_names — Required. Hydrate when present; leave zero value (nil) when absent.
			if dnsResult := gjson.Get(response, "local_auto_gen_attributes.dns_names"); dnsResult.Exists() {
				var dnsNames []types.String
				for _, v := range dnsResult.Array() {
					dnsNames = append(dnsNames, types.StringValue(v.String()))
				}
				if dnsNames == nil {
					dnsNames = []types.String{}
				}
				laga.DNSNames = dnsNames
			}
			// email_addresses — Required. Hydrate when present; leave zero value (nil) when absent.
			if emailResult := gjson.Get(response, "local_auto_gen_attributes.email_addresses"); emailResult.Exists() {
				var emails []types.String
				for _, v := range emailResult.Array() {
					emails = append(emails, types.StringValue(v.String()))
				}
				if emails == nil {
					emails = []types.String{}
				}
				laga.Emails = emails
			}
			// ip_addresses — Required. Hydrate when present; leave zero value (nil) when absent.
			if ipResult := gjson.Get(response, "local_auto_gen_attributes.ip_addresses"); ipResult.Exists() {
				var ips []types.String
				for _, v := range ipResult.Array() {
					ips = append(ips, types.StringValue(v.String()))
				}
				if ips == nil {
					ips = []types.String{}
				}
				laga.IPAddresses = ips
			}
			// names (TFIN-535): CM always returns a default names entry even when the user
			// never configured it. Only hydrate from the API response when the user previously
			// configured names (non-nil slice in prior state); otherwise preserve nil to prevent
			// perpetual drift. Matches the preserve-prior-state pattern used for uid below.
			if state.LocalAutogenAttributes.Names != nil {
				var names []NamesParamsTFSDK
				for _, n := range gjson.Get(response, "local_auto_gen_attributes.names").Array() {
					entry := NamesParamsTFSDK{}
					if r := n.Get("C"); r.Exists() {
						entry.C = types.StringValue(r.String())
					} else {
						entry.C = types.StringNull()
					}
					if r := n.Get("L"); r.Exists() {
						entry.L = types.StringValue(r.String())
					} else {
						entry.L = types.StringNull()
					}
					if r := n.Get("O"); r.Exists() {
						entry.O = types.StringValue(r.String())
					} else {
						entry.O = types.StringNull()
					}
					if r := n.Get("OU"); r.Exists() {
						entry.OU = types.StringValue(r.String())
					} else {
						entry.OU = types.StringNull()
					}
					if r := n.Get("ST"); r.Exists() {
						entry.ST = types.StringValue(r.String())
					} else {
						entry.ST = types.StringNull()
					}
					names = append(names, entry)
				}
				laga.Names = names
			} else {
				laga.Names = nil
			}
			if r := gjson.Get(response, "local_auto_gen_attributes.uid"); r.Exists() && r.String() != "" {
				laga.UID = types.StringValue(r.String())
			} else {
				// CM never returns 'uid' in GET responses (confirmed live: nae_all_9852 GET omitted it).
				// Preserve the configured value from prior state to prevent perpetual drift.
				// state.LocalAutogenAttributes is non-nil here (guarded by outer if block at line 752).
				if !state.LocalAutogenAttributes.UID.IsNull() {
					laga.UID = state.LocalAutogenAttributes.UID
				} else {
					laga.UID = types.StringNull()
				}
			}
			state.LocalAutogenAttributes = &laga
		} else {
			state.LocalAutogenAttributes = nil
		}
	} // end if state.LocalAutogenAttributes != nil

	// tls_ciphers — only hydrate when user configured it; server always returns defaults.
	if state.TLSCiphers != nil {
		if ciphersResult := gjson.Get(response, "tls_ciphers"); ciphersResult.Exists() {
			var ciphers []TLSCiphersTFSDK
			for _, c := range ciphersResult.Array() {
				ciphers = append(ciphers, TLSCiphersTFSDK{
					CipherSuite: types.StringValue(c.Get("cipher_suite").String()),
					Enabled:     types.BoolValue(c.Get("enabled").Bool()),
				})
			}
			state.TLSCiphers = ciphers
		} else {
			state.TLSCiphers = nil
		}
	}

	// registration_token — write-only; state.RegToken already holds prior value.
	// certificate — write-only; state.Certificate already holds prior value.

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_interface.go -> Read][" + id + "]")
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMInterface) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_interface.go -> Update][" + id + "]")
	var plan CMInterfaceTFSDK
	var state CMInterfaceTFSDK

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Load prior state to obtain the stable resource UUID.
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := make(map[string]interface{})

	// Scalar Optional fields: transition from non-Null in state to Null in plan -> explicit reset
	// Otherwise, if not Null in plan -> set in payload

	// allow_unregistered (Boolean)
	if !plan.AllowUnregistered.IsNull() && !plan.AllowUnregistered.IsUnknown() {
		payload["allow_unregistered"] = plan.AllowUnregistered.ValueBool()
	} else if !state.AllowUnregistered.IsNull() {
		payload["allow_unregistered"] = false // Reset to default/false
	}

	// auto_gen_ca_id (String)
	if !plan.AutogenCAId.IsNull() && !plan.AutogenCAId.IsUnknown() {
		payload["auto_gen_ca_id"] = plan.AutogenCAId.ValueString()
	} else if !state.AutogenCAId.IsNull() {
		payload["auto_gen_ca_id"] = "" // Reset/empty
	}

	// auto_gen_days_before_expiry (Int64)
	if !plan.AutogenDaysBeforeExpiry.IsNull() && !plan.AutogenDaysBeforeExpiry.IsUnknown() {
		payload["auto_gen_days_before_expiry"] = plan.AutogenDaysBeforeExpiry.ValueInt64()
	} else if !state.AutogenDaysBeforeExpiry.IsNull() {
		payload["auto_gen_days_before_expiry"] = 0 // Reset/empty
	}

	// auto_registration (Boolean)
	// Only send the explicit false when state had true — avoids a no-op false when
	// state was already false or null (CM interprets absent key as "preserve").
	if !plan.AutoRegistration.IsNull() && !plan.AutoRegistration.IsUnknown() {
		payload["auto_registration"] = plan.AutoRegistration.ValueBool()
	} else if !state.AutoRegistration.IsNull() && state.AutoRegistration.ValueBool() {
		// User removed auto_registration from config; prior state was true — clear in CM.
		payload["auto_registration"] = false
	}

	// cert_user_field (String)
	if !plan.CertUserField.IsNull() && !plan.CertUserField.IsUnknown() {
		payload["cert_user_field"] = plan.CertUserField.ValueString()
	} else if !state.CertUserField.IsNull() {
		payload["cert_user_field"] = "" // Reset/empty
	}

	// custom_uid_size (Int64)
	if !plan.CustomUIDSize.IsNull() && !plan.CustomUIDSize.IsUnknown() {
		payload["custom_uid_size"] = plan.CustomUIDSize.ValueInt64()
	} else if !state.CustomUIDSize.IsNull() {
		payload["custom_uid_size"] = 0 // Reset/empty
	}

	// custom_uid_v2 (Boolean)
	if !plan.CustomUIDv2.IsNull() && !plan.CustomUIDv2.IsUnknown() {
		payload["custom_uid_v2"] = plan.CustomUIDv2.ValueBool()
	} else if !state.CustomUIDv2.IsNull() {
		payload["custom_uid_v2"] = false // Reset/empty
	}

	// default_connection (String)
	if !plan.DefaultConnection.IsNull() && !plan.DefaultConnection.IsUnknown() {
		payload["default_connection"] = plan.DefaultConnection.ValueString()
	} else if !state.DefaultConnection.IsNull() {
		payload["default_connection"] = "" // Reset/empty
	}

	// kmip_enable_hard_delete (Int64)
	if !plan.KMIPEnableHardDelete.IsNull() && !plan.KMIPEnableHardDelete.IsUnknown() {
		payload["kmip_enable_hard_delete"] = plan.KMIPEnableHardDelete.ValueInt64()
	} else if !state.KMIPEnableHardDelete.IsNull() {
		payload["kmip_enable_hard_delete"] = 0 // Reset/empty
	}

	if plan.LocalAutogenAttributes != nil {
		var attributes CMInterfaceLocalAutogenAttrJSON
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

		payload["local_auto_gen_attributes"] = &attributes
	} else if state.LocalAutogenAttributes != nil {
		payload["local_auto_gen_attributes"] = nil
	}

	if plan.MaximumTLSVersion.ValueString() != "" && plan.MaximumTLSVersion.ValueString() != types.StringNull().ValueString() {
		payload["maximum_tls_version"] = plan.MaximumTLSVersion.ValueString()
	} else if !state.MaximumTLSVersion.IsNull() {
		payload["maximum_tls_version"] = ""
	}

	if plan.Meta != nil {
		var metadata CMInterfaceMetadataJSON
		var metadataNAE CMInterfaceMetadataNAEJSON
		if plan.Meta.NAE != nil {
			if plan.Meta.NAE.MaskSystemGroups.ValueBool() != types.BoolNull().ValueBool() {
				metadataNAE.MaskSystemGroups = plan.Meta.NAE.MaskSystemGroups.ValueBool()
				metadata.NAE = metadataNAE
			}
		}
		payload["meta"] = &metadata
	} else if state.Meta != nil {
		payload["meta"] = nil
	}

	if plan.MinimumTLSVersion.ValueString() != "" && plan.MinimumTLSVersion.ValueString() != types.StringNull().ValueString() {
		payload["minimum_tls_version"] = plan.MinimumTLSVersion.ValueString()
	} else if !state.MinimumTLSVersion.IsNull() {
		payload["minimum_tls_version"] = ""
	}

	if plan.Mode.ValueString() != "" && plan.Mode.ValueString() != types.StringNull().ValueString() {
		payload["mode"] = plan.Mode.ValueString()
	}

	if plan.NetworkInterface.ValueString() != "" && plan.NetworkInterface.ValueString() != types.StringNull().ValueString() {
		payload["network_interface"] = plan.NetworkInterface.ValueString()
	}

	// registration_token: send explicit "" clear when user removes the field and prior state
	// held a value. CM accepts PATCH {"registration_token": ""} → HTTP 200, subsequent GET
	// shows key absent (live-confirmed in ticket).
	if !plan.RegToken.IsNull() && !plan.RegToken.IsUnknown() {
		payload["registration_token"] = plan.RegToken.ValueString()
	} else if !state.RegToken.IsNull() {
		payload["registration_token"] = ""
	}

	// tls_ciphers: Null vs Empty vs Populated collection distinction
	if plan.TLSCiphers == nil {
		// Unset (Null): do not include in PATCH to avoid drift and preserve server defaults.
	} else if len(plan.TLSCiphers) == 0 {
		// Explicitly Empty: send empty array [] in PATCH to reset to server defaults.
		payload["tls_ciphers"] = []TLSCiphersJSON{}
	} else {
		// Populated: translate and include in PATCH payload
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
		payload["tls_ciphers"] = ciphers
	}

	// trusted_cas: Null vs Empty vs Populated block distinction
	if plan.TrustedCAs == nil {
		// Unset (Null): do not include in PATCH
	} else if reflect.DeepEqual((*CMInterfacTrustedCAsTFSDK)(nil), plan.TrustedCAs) {
		// Explicitly Empty: send null / clear Cas
		payload["trusted_cas"] = nil
	} else {
		// Populated: translate and include in PATCH payload
		var trustedCAsUpd CMInterfacTrustedCAsJSON
		if len(plan.TrustedCAs.External) > 0 {
			var externalCAs []string
			for _, str := range plan.TrustedCAs.External {
				externalCAs = append(externalCAs, str.ValueString())
			}
			trustedCAsUpd.External = externalCAs
		} else {
			trustedCAsUpd.External = []string{}
		}
		if len(plan.TrustedCAs.Local) > 0 {
			var localCAs []string
			for _, str := range plan.TrustedCAs.Local {
				localCAs = append(localCAs, str.ValueString())
			}
			trustedCAsUpd.Local = localCAs
		} else {
			trustedCAsUpd.Local = []string{}
		}
		payload["trusted_cas"] = &trustedCAsUpd
	}

	// certificate: send explicit null clear when user removes the block and prior state had it.
	// In Go, map[string]interface{}{"certificate": nil} marshals to {"certificate":null}.
	// certificate is absent from swagger ConfigurationUpdate AND ConfigurationAdd (undocumented
	// CM API field); nil-clear follows the same convention used for local_auto_gen_attributes
	// and meta in this Update().
	if plan.Certificate != nil {
		payload["certificate"] = &CMInterfacCertificateJSON{
			CertChain: plan.Certificate.CertChain.ValueString(),
			Generate:  plan.Certificate.Generate.ValueBool(),
			Format:    plan.Certificate.Format.ValueString(),
			Password:  plan.Certificate.Password.ValueString(),
		}
	} else if state.Certificate != nil {
		payload["certificate"] = nil
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_interface.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: interface Update",
			err.Error(),
		)
		return
	}

	// CM interface API uses NAME (not UUID) as the path key — UUID lookup returns 404.
	response, err := r.client.UpdateData(ctx, state.Name.ValueString(), common.URL_INTERFACE, payloadJSON, "updatedAt")
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_interface.go -> Update][" + state.Name.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error updating interface on CipherTrust Manager: ",
			"Could not update interface, unexpected error: "+err.Error(),
		)
		return
	}
	plan.UpdatedAt = types.StringValue(response)
	// Preserve stable Computed-only fields from prior state.
	plan.ID = state.ID
	plan.CreatedAt = state.CreatedAt
	// Preserve Optional+Computed name from prior state when user has not set it.
	if plan.Name.IsNull() || plan.Name.IsUnknown() {
		plan.Name = state.Name
	}

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_interface.go -> Update][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMInterface) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMInterfaceTFSDK
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_interface.go -> Delete][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// CM interface API uses NAME (not UUID) as the path key — UUID lookup returns 404.
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_INTERFACE, state.Name.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.Name.ValueString(), url, nil)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_interface.go -> Delete][" + state.Name.ValueString() + "][" + output + "]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			return
		}
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
