package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/validators"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/objectvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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

var (
	_ resource.Resource                = &resourceCCKMAzureCertificate{}
	_ resource.ResourceWithConfigure   = &resourceCCKMAzureCertificate{}
	_ resource.ResourceWithImportState = &resourceCCKMAzureCertificate{}
	_ resource.ResourceWithModifyPlan  = &resourceCCKMAzureCertificate{}
)

// NewResourceCCKMAzureCertificate returns a new instance of the ciphertrust_azure_certificate resource.
func NewResourceCCKMAzureCertificate() resource.Resource {
	return &resourceCCKMAzureCertificate{}
}

type resourceCCKMAzureCertificate struct {
	client *common.Client
}

func (r *resourceCCKMAzureCertificate) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_certificate"
}

func (r *resourceCCKMAzureCertificate) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

const (
	// azureCertificatesEndpoint is the CipherTrust Manager endpoint for Azure certificates.
	azureCertificatesEndpoint = common.URL_AZURE + "/certificates"
	// azureCertificateImportEndpoint is the CipherTrust Manager endpoint that uploads a certificate.
	azureCertificateImportEndpoint = azureCertificatesEndpoint + "/import"

	azureCertificateAvailable   = "AVAILABLE"
	azureCertificateFailed      = "failed"
	azureCertificateSoftDeleted = "SOFT-DELETED"

	// azureCertificatePollSeconds is the number of seconds between status checks of a new certificate.
	azureCertificatePollSeconds = 5
)

func (r *resourceCCKMAzureCertificate) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to add a certificate to a CipherTrust Manager Azure vault. " +
			"The mode is chosen by which block is set. Only one block can be set.\n\n" +
			"- No block (default): creates a new certificate in the vault from azure_params.\n" +
			"- upload_certificate: imports an existing certificate and private key.\n" +
			"- restore_certificate: restores a purged certificate from the backup of the latest version " +
			"retained in CipherTrust Manager, into the vault nominated by vault_id.\n\n" +
			"All inputs are immutable except `azure_params.tags` and `azure_params.policy.attributes.enabled`, " +
			"which are updated in place.\n\n" +
			"To create a new version of a certificate, create another certificate resource with the same name.\n\n" +
			"If a soft-deleted certificate of the same name exists in the vault, creating the resource recovers it " +
			"instead of creating a new certificate. Importing a soft-deleted certificate also recovers it. " +
			"Both require `recover_soft_deleted_certificates` to be true in the provider settings, otherwise they fail.\n\n" +
			"On destroy, the certificate is soft-deleted and, if purge_certificates_on_delete is true in the provider settings (the default) and the vault supports purge, purged. If it is false, the certificate is only soft-deleted.",
		Attributes: map[string]schema.Attribute{
			// Inputs
			"name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "(Immutable) Name of the certificate. May contain only alphanumeric characters and hyphens. " +
					"Required unless restore_certificate is set, in which case it cannot be set.",
				Validators: []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableString(),
				},
			},
			"vault_id": schema.StringAttribute{
				Required: true,
				Description: "(Conditionally immutable) CipherTrust Manager resource ID of the Azure vault that contains the certificate. " +
					"Can only be changed if the previously configured vault no longer exists in CipherTrust Manager. " +
					"When restore_certificate is set this is the vault the certificate is restored to; it can be any vault. " +
					"A vault name is not accepted.",
				Validators: []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
			},
			"restore_certificate": schema.SingleNestedAttribute{
				Optional: true,
				Description: "(Immutable) Restores a purged certificate into `vault_id` instead of creating a new one. " +
					"Cannot be combined with `name`, `azure_params` or `upload_certificate`.",
				PlanModifiers: []planmodifier.Object{
					modifiers.ImmutableObject(),
				},
				Attributes: map[string]schema.Attribute{
					"certificate_id": schema.StringAttribute{
						Required: true,
						Description: "CipherTrust Manager resource ID of the purged certificate to restore. " +
							"It is no longer in Terraform state.",
						Validators: []validator.String{stringvalidator.RegexMatches(regexp.MustCompile(`\S`), "must contain at least one non-whitespace character")},
					},
				},
			},
			"upload_certificate": schema.SingleNestedAttribute{
				Optional: true,
				Description: "(Immutable) Uploads a certificate to the vault instead of creating a new one. " +
					"There are two ways to upload. Either set `source_cert_id`, `ca_id` and `private_key_pem` to upload a certificate " +
					"signed by a CipherTrust Manager CA, or set `certificate` to upload an external certificate " +
					"(a PEM certificate with `private_key_pem`, or a PFX). " +
					"`certificate` cannot be combined with `source_cert_id` or `ca_id`. " +
					"Only `azure_params.tags` can be set with it. Cannot be combined with `azure_params.policy` or `restore_certificate`. " +
					"This attribute is not supported in CDSPaaS.",
				Validators: []validator.Object{
					objectvalidator.ConflictsWith(path.MatchRoot("azure_params").AtName("policy")),
					objectvalidator.ConflictsWith(path.MatchRoot("restore_certificate")),
				},
				Attributes: map[string]schema.Attribute{
					"source_cert_id": schema.StringAttribute{
						Optional: true,
						Computed: true,
						Description: "(Immutable) CipherTrust Manager resource ID of the certificate to upload. Requires ca_id and private_key_pem. Cannot be used with certificate. " +
							"The value is kept as configured. It is not read back from CipherTrust Manager. " +
							"This attribute is not supported in CDSPaaS.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
							modifiers.ImmutableStringUnlessNull(),
						},
						Validators: []validator.String{
							stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("ca_id")),
							stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("private_key_pem")),
							stringvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("certificate")),
						},
					},
					"ca_id": schema.StringAttribute{
						Optional:    true,
						Description: "(Immutable) CipherTrust Manager resource ID of the CA that signed the certificate. Requires source_cert_id. Cannot be used with certificate. This attribute is not supported in CDSPaaS.",
						PlanModifiers: []planmodifier.String{
							modifiers.ImmutableStringUnlessNull(),
						},
						Validators: []validator.String{
							stringvalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("source_cert_id")),
						},
					},
					"certificate": schema.StringAttribute{
						Optional:  true,
						Sensitive: true,
						PlanModifiers: []planmodifier.String{
							modifiers.ImmutableSensitiveString(),
						},
						Description: "(Immutable) External certificate to upload. Cannot be used with source_cert_id or ca_id. Can be PEM content, the path to a PEM or PFX file, " +
							"or a base64 encoded PFX. Requires private_key_pem when it is a PEM certificate. " +
							"A path is read by the provider, relative to the directory Terraform runs from. " +
							"A PFX file is base64 encoded by the provider. A base64 encoded PFX is sent as is.",
					},
					"private_key_pem": schema.StringAttribute{
						Optional:  true,
						Sensitive: true,
						PlanModifiers: []planmodifier.String{
							modifiers.ImmutableSensitiveString(),
						},
						Description: "(Immutable) Private key of the certificate, as PEM content or the path to a PEM file. " +
							"Required with source_cert_id and ca_id, or with a PEM certificate. Not used with a PFX. " +
							"A path is read by the provider, relative to the directory Terraform runs from.",
					},
					"private_key_password": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "(Immutable) Password used to decrypt private_key_pem or the PFX in certificate, if it is encrypted.",
						PlanModifiers: []planmodifier.String{
							modifiers.ImmutableSensitiveString(),
						},
					},
				},
			},
			// Every azure_params value is Optional and Computed.
			"azure_params": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Description: "Azure certificate parameters. Only `tags` and `policy.attributes.enabled` can be updated, everything else " +
					"is immutable. `policy` is required unless `upload_certificate` " +
					"is set. When `upload_certificate` is set only `tags` can be set. " +
					"Cannot be set when `restore_certificate` is set.",
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"tags": schema.MapAttribute{
						Optional:    true,
						Computed:    true,
						ElementType: types.StringType,
						Description: "Application specific metadata in the form of key-value pairs. Can be updated. " +
							"An update replaces the whole set of tags. Removing the attribute from the configuration does not clear " +
							"the tags, set it to an empty map (`tags = {}`) to remove all tags.",
						PlanModifiers: []planmodifier.Map{
							mapplanmodifier.UseStateForUnknown(),
						},
					},
					"policy": schema.SingleNestedAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Certificate policy. Only `attributes.enabled` can be updated, everything else is immutable.",
						PlanModifiers: []planmodifier.Object{
							objectplanmodifier.UseStateForUnknown(),
						},
						Attributes: map[string]schema.Attribute{
							"issuer": schema.SingleNestedAttribute{
								Optional:    true,
								Computed:    true,
								Description: "Issuer of the certificate.",
								PlanModifiers: []planmodifier.Object{
									objectplanmodifier.UseStateForUnknown(),
								},
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Required: true,
										PlanModifiers: []planmodifier.String{
											modifiers.ImmutableString(),
										},
										Description: "(Immutable) Name of the issuer. Set to Self for a self-signed certificate.",
									},
									"certificate_type": schema.StringAttribute{
										Optional:    true,
										Computed:    true,
										Description: "(Immutable) Optional certificate type that is specific to the issuer, for example OV-SSL or EV-SSL. Not used by the Self issuer.",
										PlanModifiers: []planmodifier.String{
											stringplanmodifier.UseStateForUnknown(),
											modifiers.ImmutableString(),
										},
									},
									"cert_transparency": schema.BoolAttribute{
										Optional:    true,
										Computed:    true,
										Description: "(Immutable) Whether the certificate is published to certificate transparency logs. Not valid for the Self issuer.",
										PlanModifiers: []planmodifier.Bool{
											boolplanmodifier.UseStateForUnknown(),
											modifiers.ImmutableBool(),
										},
									},
								},
							},
							"key_props": schema.SingleNestedAttribute{
								Optional:      true,
								Computed:      true,
								Description:   "Properties of the key backing the certificate.",
								PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
								Attributes: map[string]schema.Attribute{
									"kty": schema.StringAttribute{
										Required: true,
										PlanModifiers: []planmodifier.String{
											modifiers.ImmutableString(),
										},
										Description: "(Immutable) Key type. Options are EC, EC-HSM, RSA and RSA-HSM.",
										Validators:  []validator.String{stringvalidator.OneOf("EC", "EC-HSM", "RSA", "RSA-HSM")},
									},
									"curve": schema.StringAttribute{
										Optional:    true,
										Computed:    true,
										Description: "(Immutable) Elliptic curve name. Options are P-256, P-384, P-521 and SECP256K1.",
										Validators:  []validator.String{stringvalidator.OneOf("P-256", "P-384", "P-521", "SECP256K1")},
										PlanModifiers: []planmodifier.String{
											stringplanmodifier.UseStateForUnknown(),
											modifiers.ImmutableString(),
										},
									},
									"exportable": schema.BoolAttribute{
										Optional:    true,
										Computed:    true,
										Description: "(Immutable) Whether the private key can be exported. Not valid for HSM keys.",
										PlanModifiers: []planmodifier.Bool{
											boolplanmodifier.UseStateForUnknown(),
											modifiers.ImmutableBool(),
										},
									},
									"key_size": schema.Int64Attribute{
										Optional:    true,
										Computed:    true,
										Description: "(Immutable) Size of an RSA key. Options are 2048, 3072 and 4096.",
										Validators:  []validator.Int64{int64validator.OneOf(2048, 3072, 4096)},
										PlanModifiers: []planmodifier.Int64{
											int64planmodifier.UseStateForUnknown(),
											modifiers.ImmutableInt64(),
										},
									},
									"reuse_key": schema.BoolAttribute{
										Optional:    true,
										Computed:    true,
										Description: "(Immutable) Whether the same key pair is used when the certificate is renewed.",
										PlanModifiers: []planmodifier.Bool{
											boolplanmodifier.UseStateForUnknown(),
											modifiers.ImmutableBool(),
										},
									},
								},
							},
							"x509_props": schema.SingleNestedAttribute{
								Optional:      true,
								Computed:      true,
								Description:   "X509 properties of the certificate.",
								PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
								Attributes: map[string]schema.Attribute{
									"subject": schema.StringAttribute{
										Required: true,
										PlanModifiers: []planmodifier.String{
											modifiers.ImmutableString(),
										},
										Description: "(Immutable) Subject name. Must be a valid X509 distinguished name.",
									},
									"enhanced_key_usage": schema.ListAttribute{
										Optional:    true,
										Computed:    true,
										ElementType: types.StringType,
										Description: "(Immutable) Enhanced key usage object identifiers.",
										PlanModifiers: []planmodifier.List{
											listplanmodifier.UseStateForUnknown(),
											modifiers.ImmutableList(),
										},
									},
									"key_usage": schema.ListAttribute{
										Optional:    true,
										Computed:    true,
										ElementType: types.StringType,
										Description: "(Immutable) Allowed key usages. For example digitalSignature or keyEncipherment.",
										PlanModifiers: []planmodifier.List{
											listplanmodifier.UseStateForUnknown(),
											modifiers.ImmutableList(),
										},
									},
									"validity_months": schema.Int64Attribute{
										Optional:    true,
										Computed:    true,
										Description: "(Immutable) Number of months the certificate is valid for.",
										PlanModifiers: []planmodifier.Int64{
											int64planmodifier.UseStateForUnknown(),
											modifiers.ImmutableInt64(),
										},
									},
									"sans": schema.SingleNestedAttribute{
										Optional:      true,
										Computed:      true,
										Description:   "Subject alternative names.",
										PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
										Attributes: map[string]schema.Attribute{
											"dns_names": schema.ListAttribute{
												Optional:    true,
												Computed:    true,
												ElementType: types.StringType,
												Description: "(Immutable) Domain names.",
												PlanModifiers: []planmodifier.List{
													listplanmodifier.UseStateForUnknown(),
													modifiers.ImmutableList(),
												},
											},
											"emails": schema.ListAttribute{
												Optional:    true,
												Computed:    true,
												ElementType: types.StringType,
												Description: "(Immutable) Email addresses.",
												PlanModifiers: []planmodifier.List{
													listplanmodifier.UseStateForUnknown(),
													modifiers.ImmutableList(),
												},
											},
											"user_principal_names": schema.ListAttribute{
												Optional:    true,
												Computed:    true,
												ElementType: types.StringType,
												Description: "(Immutable) User principal names.",
												PlanModifiers: []planmodifier.List{
													listplanmodifier.UseStateForUnknown(),
													modifiers.ImmutableList(),
												},
											},
										},
									},
								},
							},
							"attributes": schema.SingleNestedAttribute{
								Optional:      true,
								Computed:      true,
								Description:   "Attributes of the certificate.",
								PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
								Attributes: map[string]schema.Attribute{
									"enabled": schema.BoolAttribute{
										Optional:    true,
										Computed:    true,
										Description: "Whether the certificate is enabled. Can be updated.",
										PlanModifiers: []planmodifier.Bool{
											boolplanmodifier.UseStateForUnknown(),
										},
									},
									"activation_date": schema.StringAttribute{
										Optional: true,
										Description: "(Immutable) Date of certificate activation in UTC time in RFC3339 format. For example, 2026-07-03T14:24:00Z. " +
											"Before this time the certificate cannot be used.",
										Validators:    []validator.String{validators.RFC3339()},
										PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
									},
									"expiration_date": schema.StringAttribute{
										Optional: true,
										Description: "(Immutable) Date of certificate expiry in UTC time in RFC3339 format. For example, 2030-07-03T14:24:00Z. " +
											"Must be later than activation_date.",
										Validators:    []validator.String{validators.RFC3339()},
										PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
									},
								},
							},
							"secret_props": schema.SingleNestedAttribute{
								Optional:      true,
								Computed:      true,
								Description:   "Properties of the secret backing the certificate.",
								PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
								Attributes: map[string]schema.Attribute{
									"content_type": schema.StringAttribute{
										Optional:    true,
										Computed:    true,
										Description: "(Immutable) Content type of the certificate. For example application/x-pkcs12 or application/x-pem-file.",
										PlanModifiers: []planmodifier.String{
											stringplanmodifier.UseStateForUnknown(),
											modifiers.ImmutableString(),
										},
									},
								},
							},
							// Azure allows one lifetime action.
							"lifetime_actions": schema.ListNestedAttribute{
								Optional:    true,
								Computed:    true,
								Description: "(Immutable) Actions to perform on the certificate during its lifetime. Only one action is allowed.",
								// Immutability is enforced in ModifyPlan, after the nested computed values are resolved.
								// A list level ImmutableList would see unknown nested values and reject unchanged lists.
								PlanModifiers: []planmodifier.List{
									listplanmodifier.UseStateForUnknown(),
								},
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"trigger": schema.SingleNestedAttribute{
											Optional:      true,
											Computed:      true,
											Description:   "Condition that runs the action. Set either lifetime_percentage or days_before_expiry.",
											PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
											Attributes: map[string]schema.Attribute{
												"lifetime_percentage": schema.Int64Attribute{
													Optional:    true,
													Computed:    true,
													Description: "(Immutable) Percentage of the lifetime at which the action runs. Between 1 and 99.",
													Validators:  []validator.Int64{int64validator.Between(1, 99)},
													PlanModifiers: []planmodifier.Int64{
														int64planmodifier.UseStateForUnknown(),
													},
												},
												"days_before_expiry": schema.Int64Attribute{
													Optional:    true,
													Computed:    true,
													Description: "(Immutable) Number of days before expiry at which the action runs.",
													PlanModifiers: []planmodifier.Int64{
														int64planmodifier.UseStateForUnknown(),
													},
												},
											},
										},
										"action": schema.SingleNestedAttribute{
											Optional:      true,
											Computed:      true,
											Description:   "Action to perform.",
											PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
											Attributes: map[string]schema.Attribute{
												"action_type": schema.StringAttribute{
													Required:    true,
													Description: "(Immutable) Type of the action. Options are AutoRenew and EmailContacts.",
													Validators:  []validator.String{stringvalidator.OneOf("AutoRenew", "EmailContacts")},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},

			// Computed attributes.
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "CipherTrust Manager resource ID of the certificate.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the certificate was created in CipherTrust Manager.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the certificate was last updated in CipherTrust Manager.",
			},
			"synced_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the certificate was last synchronized with Azure.",
			},
			"rotated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the certificate was last rotated.",
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Status of the certificate.",
			},
			"version": schema.StringAttribute{
				Computed:    true,
				Description: "Azure version of the certificate.",
			},
			"version_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of versions of the certificate.",
			},
			"operation": schema.StringAttribute{
				Computed:    true,
				Description: "Last operation performed on the certificate.",
			},
			"operation_error": schema.StringAttribute{
				Computed:    true,
				Description: "Error of the last operation, if it failed.",
			},
			"error": schema.StringAttribute{
				Computed:    true,
				Description: "Error reported for the certificate.",
			},
			"deleted": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the certificate is deleted.",
			},
			"gone": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the certificate no longer exists in Azure.",
			},
			"cert_soft_deleted_in_azure": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the certificate is soft-deleted in Azure.",
			},
			"cert_material_origin": schema.StringAttribute{
				Computed:    true,
				Description: "Origin of the certificate material.",
			},
			"cert_source": schema.StringAttribute{
				Computed:    true,
				Description: "Source of the certificate.",
			},
			"backup": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager resource ID of the Azure certificate backup.",
			},
			"backup_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the certificate was last backed up.",
			},
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "Azure cloud of the vault.",
			},
			"region": schema.StringAttribute{
				Computed:    true,
				Description: "Azure region of the vault.",
			},
			"tenant": schema.StringAttribute{
				Computed:    true,
				Description: "Azure tenant of the vault.",
			},
			"vault_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the Azure vault that contains the certificate.",
			},
			"soft_delete_enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether soft delete is enabled on the vault.",
			},
			"azure_created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the certificate was created in Azure.",
			},
			"azure_updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the certificate was last updated in Azure.",
			},
			"azure_expire_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the certificate expires.",
			},
			"cert": schema.StringAttribute{
				Computed:    true,
				Description: "Base64 encoded certificate (CER).",
			},
			"cid": schema.StringAttribute{
				Computed:    true,
				Description: "Azure identifier of the certificate.",
			},
			"kid": schema.StringAttribute{
				Computed:    true,
				Description: "Azure identifier of the key backing the certificate.",
			},
			"sid": schema.StringAttribute{
				Computed:    true,
				Description: "Azure identifier of the secret backing the certificate.",
			},
			"thumbprint": schema.StringAttribute{
				Computed:    true,
				Description: "Thumbprint of the certificate.",
			},
			"recovery_level": schema.StringAttribute{
				Computed:    true,
				Description: "Azure recovery level of the certificate.",
			},
			"recoverable_days": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of days a soft-deleted certificate can be recovered.",
			},
		},
	}
}

// Create creates a native certificate, recovers a soft-deleted one of the same name, or uploads a certificate.
// The vault is fetched first so that vault_id is confirmed to be a CipherTrust Manager vault resource ID.
func (r *resourceCCKMAzureCertificate) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_certificate.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_certificate.go -> Create][" + id + "]")

	var plan AzureCertificateTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := plan.VaultID.ValueString()
	vaultResp := getAzureVault(ctx, id, r.client, vaultID, "creating certificate in", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if gjson.Get(vaultResp, "id").String() != vaultID {
		details := utils.ApiError(
			"Error creating Azure certificate: vault_id must be the CipherTrust Manager resource ID of an Azure vault.",
			map[string]interface{}{"vault_id": vaultID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	mutexKey := fmt.Sprintf("azure-certificate-%s", vaultID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	var response string
	switch {
	case plan.RestoreCertificate != nil:
		response = restoreAzureCertificate(ctx, id, r.client, plan.RestoreCertificate.CertificateID.ValueString(), vaultID, &resp.Diagnostics)
	case plan.UploadCertificate != nil:
		response = uploadAzureCertificate(ctx, id, r.client, &plan, &resp.Diagnostics)
	default:
		response = createNativeAzureCertificate(ctx, id, r.client, &plan, &resp.Diagnostics)
	}
	if response == "" || resp.Diagnostics.HasError() {
		return
	}

	// Read the certificate back so that state is built from the same response as Read.
	response = getAzureCertificate(ctx, id, r.client, gjson.Get(response, "id").String(), "creating", &resp.Diagnostics)
	if response == "" || resp.Diagnostics.HasError() {
		return
	}

	if err := azureCertificateSetState(response, &plan); err != nil {
		details := utils.ApiError("Error creating Azure certificate, failed to parse the response.",
			map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the certificate state from CipherTrust Manager. A 404 is a hard error.
func (r *resourceCCKMAzureCertificate) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_certificate.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_certificate.go -> Read][" + id + "]")

	var state AzureCertificateTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response := getAzureCertificate(ctx, id, r.client, state.ID.ValueString(), "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := azureCertificateSetState(response, &state); err != nil {
		details := utils.ApiError("Error reading Azure certificate, failed to parse the response.",
			map[string]interface{}{"error": err.Error(), "certificate_id": state.ID.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// ImportState imports a certificate using its CipherTrust Manager resource ID. Read populates the rest.
// A soft-deleted certificate is recovered first when recover_soft_deleted_certificates is true, otherwise
// the import fails, because a soft-deleted certificate cannot be used.
func (r *resourceCCKMAzureCertificate) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_certificate.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_certificate.go -> ImportState][" + id + "]")

	existing := getAzureCertificate(ctx, id, r.client, req.ID, "importing", &resp.Diagnostics)
	if existing == "" || resp.Diagnostics.HasError() {
		return
	}
	if gjson.Get(existing, "status").String() == azureCertificateSoftDeleted {
		if !r.client.CCKMConfig.AzureCCKMSettings.RecoverSoftDeletedCertificates {
			details := utils.ApiError(
				"Error importing Azure certificate. The certificate is soft-deleted and cannot be imported as is. "+
					"Set the provider option of recover_soft_deleted_certificates to true in the provider settings and import again.",
				map[string]interface{}{"name": gjson.Get(existing, "name").String(), "certificate_id": req.ID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		mutexKey := fmt.Sprintf("azure-certificate-%s", gjson.Get(existing, "key_vault_id").String())
		mutex.CckmMutex.Lock(mutexKey)
		defer mutex.CckmMutex.Unlock(mutexKey)

		if recovered := recoverSoftDeletedAzureCertificate(ctx, id, r.client, existing, &resp.Diagnostics); recovered == "" || resp.Diagnostics.HasError() {
			return
		}
	}

	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// Update changes azure_params.tags and azure_params.policy.attributes.enabled with a single PATCH. Every
// other input is immutable and is rejected at plan time.
func (r *resourceCCKMAzureCertificate) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_certificate.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_certificate.go -> Update][" + id + "]")

	var plan, state AzureCertificateTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mutexKey := fmt.Sprintf("azure-certificate-%s", state.VaultID.ValueString())
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	certID := state.ID.ValueString()
	response := getAzureCertificate(ctx, id, r.client, certID, "updating", &resp.Diagnostics)
	if response == "" || resp.Diagnostics.HasError() {
		return
	}

	// Only the parts that differ between plan and state are sent: tags and attributes.enabled.
	// A tags change sends the full planned set, which replaces the existing tags, and an empty set is
	// sent as {} to clear them.
	updateBody := map[string]interface{}{}
	planParams := objectAttrs(plan.AzureParams)
	stateParams := objectAttrs(state.AzureParams)
	if planParams != nil {
		planTags := attrMap(planParams, "tags")
		if !planTags.IsUnknown() && !planTags.Equal(attrMap(stateParams, "tags")) {
			tags := azureCertificateTagsPayload(planTags)
			if tags == nil {
				tags = map[string]string{}
			}
			updateBody["tags"] = tags
		}
		planEnabled := attrBool(objectAttrs(objectAttrs(planParams["policy"])["attributes"]), "enabled")
		stateEnabled := attrBool(objectAttrs(objectAttrs(stateParams["policy"])["attributes"]), "enabled")
		if !planEnabled.IsNull() && !planEnabled.IsUnknown() && !planEnabled.Equal(stateEnabled) {
			updateBody["attributes"] = map[string]bool{"enabled": planEnabled.ValueBool()}
		}
	}

	if len(updateBody) > 0 {
		payload, err := json.Marshal(updateBody)
		if err != nil {
			details := utils.ApiError("Error updating Azure certificate, failed to build the request.",
				map[string]interface{}{"error": err.Error(), "certificate_id": certID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		patchResponse, err := azureUpdateDataV2WithRetry(ctx, id, r.client, azureCertificatesEndpoint, certID, payload)
		if err != nil {
			details := utils.ApiError("Error updating Azure certificate.",
				map[string]interface{}{"error": err.Error(), "certificate_id": certID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		r.client.Log.Debug("[resource_azure_certificate.go -> Update][" + id + "][patch response:" + redactAzureCertResponse(patchResponse) + "]")
		// The response read before the PATCH is stale, so read the certificate again to get the new values.
		response = getAzureCertificate(ctx, id, r.client, certID, "updating", &resp.Diagnostics)
		if response == "" || resp.Diagnostics.HasError() {
			return
		}
	}

	r.client.Log.Debug("[resource_azure_certificate.go -> Update][response:" + response + "]")
	// vault_id is conditionally immutable. When it was repointed because the old vault no longer exists,
	// the response may still carry the old vault, so the planned value is kept.
	plannedVaultID := plan.VaultID
	if err := azureCertificateSetState(response, &plan); err != nil {
		details := utils.ApiError("Error updating Azure certificate, failed to parse the response.",
			map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	plan.VaultID = plannedVaultID
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete soft-deletes a certificate and, when purge_certificates_on_delete is true and the certificate is
// purgeable, purges it. A purge straight after a soft-delete can return 409, so the POSTs are retried.
func (r *resourceCCKMAzureCertificate) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_certificate.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_certificate.go -> Delete][" + id + "]")

	var state AzureCertificateTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	certID := state.ID.ValueString()
	response := getAzureCertificate(ctx, id, r.client, certID, "deleting", &resp.Diagnostics)
	if resp.Diagnostics.HasError() || response == "" {
		return
	}

	vaultID := gjson.Get(response, "key_vault_id").String()
	name := gjson.Get(response, "cert_name").String()
	mutexKey := fmt.Sprintf("azure-certificate-%s", vaultID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	r.client.Log.Debug("[resource_azure_certificate.go -> Delete][" + id + "] Certificate before delete: status=" +
		gjson.Get(response, "status").String() +
		" deleted=" + gjson.Get(response, "deleted").String() +
		" cert_soft_deleted_in_azure=" + gjson.Get(response, "cert_soft_deleted_in_azure").String() +
		" recovery_level=" + gjson.Get(response, "azure_param.attributes.recovery_level").String())

	// Each step is done only if it is still needed, so a destroy operation that failed part way can be run again.
	purged := gjson.Get(response, "deleted").Bool()
	softDeleted := gjson.Get(response, "cert_soft_deleted_in_azure").Bool()
	if purged {
		return
	}
	if !softDeleted {
		softDelResponse, err := azurePostNoDataWithRetry(ctx, id, r.client, azureCertificatesEndpoint+"/"+certID+"/soft-delete")
		if err != nil {
			details := utils.ApiError("Error soft deleting Azure certificate.",
				map[string]interface{}{"error": err.Error(), "certificate_id": certID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		r.client.Log.Info("[resource_azure_certificate.go -> Delete][" + id + "] Soft deleted Azure certificate " + name)
		r.client.Log.Debug("[resource_azure_certificate.go -> Soft-Delete][" + id + "][response:" + redactAzureCertResponse(softDelResponse) + "]")
	}

	recoveryLevel := gjson.Get(response, "azure_param.attributes.recoveryLevel").String()
	if recoveryLevel == "" {
		recoveryLevel = gjson.Get(response, "azure_param.attributes.recovery_level").String()
	}
	if !strings.Contains(recoveryLevel, "Purgeable") {
		r.client.Log.Info("[resource_azure_certificate.go -> Delete][" + id + "] Not purging " + name + " as the certificate is not purgeable")
		return
	}
	if !r.client.CCKMConfig.AzureCCKMSettings.PurgeCertificatesOnDelete {
		r.client.Log.Info("[resource_azure_certificate.go -> Delete][" + id + "] Not purging " + name + " as purge_certificates_on_delete is false")
		return
	}
	purgeResponse, err := azurePostNoDataWithRetry(ctx, id, r.client, azureCertificatesEndpoint+"/"+certID+"/hard-delete")
	if err != nil {
		details := utils.ApiError("Error purging Azure certificate.",
			map[string]interface{}{"error": err.Error(), "certificate_id": certID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.client.Log.Info("[resource_azure_certificate.go -> Delete][" + id + "] Purged Azure certificate " + name)
	r.client.Log.Debug("[resource_azure_certificate.go -> Purge][" + id + "][response:" + redactAzureCertResponse(purgeResponse) + "]")
}

// ModifyPlan checks that the configuration has a restore_certificate, or a name
// with either an upload_certificate or an azure_params policy to create from.
func (r *resourceCCKMAzureCertificate) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_certificate.go -> ModifyPlan]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_certificate.go -> ModifyPlan]")

	defer func() {
		if resp.Diagnostics.HasError() || req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
			return
		}
		// The framework marks unconfigured Optional+Computed attributes as unknown, which leaves a non-empty
		// plan after apply. See azureCertificateUseStateWhenUnchanged. It is deferred so that it runs after
		// every return below and so that validation errors win.
		resp.Plan.Raw = azureCertificateUseStateWhenUnchanged(resp.Plan.Raw, req.State.Raw)
	}()

	// destroy - nothing to validate
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan AzureCertificateTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// On update only azure_params.tags and azure_params.policy.attributes.enabled can change.
	if !req.State.Raw.IsNull() {
		var state AzureCertificateTFSDK
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if !azureVaultChangeAllowed(ctx, uuid.New().String(), r.client, state.VaultID, plan.VaultID, &resp.Diagnostics) {
			return
		}
		// The per attribute modifiers do not see the block itself being removed. Adding it is allowed
		// because state has no upload_certificate after an import. The immutable modifiers on its
		// attributes (ImmutableStringUnlessNull, ImmutableSensitiveString) allow the first set from null.
		if plan.UploadCertificate == nil && state.UploadCertificate != nil {
			resp.Diagnostics.AddAttributeError(path.Root("upload_certificate"), "Attribute is immutable",
				"upload_certificate cannot be removed after creation. "+
					"To change this attribute, destroy and recreate the resource.")
			return
		}
		planParams := objectAttrs(plan.AzureParams)
		stateParams := objectAttrs(state.AzureParams)
		planPolicy, planOK := planParams["policy"].(types.Object)
		statePolicy, stateOK := stateParams["policy"].(types.Object)
		if planOK && stateOK && azureCertificatePolicyChanged(planPolicy, statePolicy) {
			resp.Diagnostics.AddAttributeError(path.Root("azure_params").AtName("policy"), "Attribute is immutable",
				"azure_params.policy cannot be changed after creation except for policy.attributes.enabled. "+
					"To change anything else, destroy and recreate the resource.")
			return
		}
	}
	// Name and azure_params are computed, so the configuration shows what the user set.
	var cfg AzureCertificateTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// CDSPaaS has no certificate upload endpoint.
	if r.client != nil && r.client.IsCDSPaaS && cfg.UploadCertificate != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("upload_certificate"),
			"'upload_certificate' is not supported on CDSPaaS",
			"The 'upload_certificate' attribute is only supported on on-premises CipherTrust Manager. "+
				"CDSPaaS does not support uploading a certificate; this attribute must be omitted.",
		)
		return
	}
	// Report everything that is missing and everything that is not allowed for the mode in one error.
	hasState := !req.State.Raw.IsNull()
	blockPath, mode, missing, notAllowed := azureCertificateModeCheck(&cfg, hasState)
	if addAzureCertificateModeError(&resp.Diagnostics, blockPath, mode, missing, notAllowed) {
		return
	}
	// Restore and upload have nothing more to check.
	if cfg.RestoreCertificate != nil || cfg.UploadCertificate != nil {
		return
	}
	policy := objectAttrs(objectAttrs(plan.AzureParams)["policy"])
	actions, _ := policy["lifetime_actions"].(types.List)
	if len(actions.Elements()) > 1 {
		details := utils.ApiError(
			"Invalid Azure certificate plan: azure_params.policy.lifetime_actions can contain only one action.",
			map[string]interface{}{"name": plan.Name.ValueString(), "actions": len(actions.Elements())})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
	}
}

// createNativeAzureCertificate creates a certificate from azure_params and waits for it to be available.
// It returns the response of the available certificate.
func createNativeAzureCertificate(ctx context.Context, id string, client *common.Client, plan *AzureCertificateTFSDK, diags *diag.Diagnostics) string {
	name := plan.Name.ValueString()
	existing := findAzureCertificate(ctx, id, client, plan.VaultID.ValueString(), name, diags)
	if diags.HasError() {
		return ""
	}
	if gjson.Get(existing, "status").String() == azureCertificateSoftDeleted &&
		client.CCKMConfig.AzureCCKMSettings.RecoverSoftDeletedCertificates {
		// Recover only makes the soft-deleted certificate available again. The certificate is returned as is
		// and nothing is created, so its ID and version are unchanged. When recover_soft_deleted_certificates
		// is false the create below goes ahead and fails because the name is still held by the soft-deleted
		// certificate.
		return recoverSoftDeletedAzureCertificate(ctx, id, client, existing, diags)
	}
	payloadJSON, err := json.Marshal(azureCertificateCreatePayload(plan))
	if err != nil {
		details := utils.ApiError("Error creating Azure certificate, invalid request.",
			map[string]interface{}{"error": err.Error(), "name": name})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	response, err := azurePostDataV2WithRetry(ctx, id, client, azureCertificatesEndpoint, payloadJSON)
	if err != nil {
		details := utils.ApiError("Error creating Azure certificate.",
			map[string]interface{}{"error": err.Error(), "name": name})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	certID := gjson.Get(response, "id").String()
	if certID == "" {
		details := utils.ApiError("Error creating Azure certificate, the response did not contain a certificate ID.",
			map[string]interface{}{"name": name})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	client.Log.Debug("[azure_certificate_ops.go -> Create][response:" + redactAzureCertResponse(response) + "]")
	return waitForAzureCertificate(ctx, id, client, certID, diags)
}

// uploadAzureCertificate uploads a certificate. The import is synchronous.
func uploadAzureCertificate(ctx context.Context, id string, client *common.Client, plan *AzureCertificateTFSDK, diags *diag.Diagnostics) string {
	importPayload, err := azureCertificateImportPayload(plan)
	if err != nil {
		details := utils.ApiError("Error uploading Azure certificate, unable to read file.",
			map[string]interface{}{"error": err.Error(), "name": plan.Name.ValueString()})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	payloadJSON, err := json.Marshal(importPayload)
	if err != nil {
		details := utils.ApiError("Error uploading Azure certificate, invalid request.",
			map[string]interface{}{"error": err.Error(), "name": plan.Name.ValueString()})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	response, err := azurePostDataV2WithRetry(ctx, id, client, azureCertificateImportEndpoint, payloadJSON)
	if err != nil {
		details := utils.ApiError("Error uploading Azure certificate.",
			map[string]interface{}{"error": err.Error(), "name": plan.Name.ValueString()})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	client.Log.Debug("[azure_certificate_ops.go -> Upload][response:" + redactAzureCertResponse(response) + "]")
	return response
}

// recoverSoftDeletedAzureCertificate recovers a soft-deleted certificate. existing is the JSON of the
// soft-deleted certificate. The callers check that recover_soft_deleted_certificates is true before calling it.
// It is used by create, when a soft-deleted certificate of the same name exists, and by import. The recovered
// certificate keeps its ID and nothing new is created.
// It waits for the certificate to be available and returns its response, or "" with an error in diags.
func recoverSoftDeletedAzureCertificate(ctx context.Context, id string, client *common.Client, existing string, diags *diag.Diagnostics) string {
	certID := gjson.Get(existing, "id").String()
	endpoint := azureCertificatesEndpoint + "/" + certID + "/recover"
	client.Log.Debug("[azure_certificate_ops.go -> recoverSoftDeletedAzureCertificate][" + id + "][request: POST " + endpoint +
		", payload: {}, certificate_id: " + certID + ", vault_id: " + gjson.Get(existing, "key_vault_id").String() + "]")
	response, err := azurePostDataV2WithRetry(ctx, id, client, endpoint, []byte("{}"))
	if err != nil {
		details := utils.ApiError("Error recovering soft-deleted Azure certificate.",
			map[string]interface{}{"error": err.Error(), "certificate_id": certID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	client.Log.Debug("[azure_certificate_ops.go -> recoverSoftDeletedAzureCertificate][" + id + "][response:" + redactAzureCertResponse(response) + "]")
	return waitForAzureCertificate(ctx, id, client, certID, diags)
}

// restoreAzureCertificate restores a certificate from its backup into the vault. restoreID is the
// CipherTrust Manager ID of the certificate to restore. The restore is synchronous and the certificate
// keeps its ID. CipherTrust Manager rejects the request if the certificate cannot be restored.
// On failure an error diagnostic is added and "" is returned.
func restoreAzureCertificate(ctx context.Context, id string, client *common.Client, restoreID string, vaultID string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[azure_certificate_ops.go -> restoreAzureCertificate][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[azure_certificate_ops.go -> restoreAzureCertificate][" + id + "]")

	payloadJSON, err := json.Marshal(models.AzureRestoreCertificatePayloadJSON{KeyVault: vaultID})
	if err != nil {
		details := utils.ApiError("Error restoring Azure certificate, invalid request.",
			map[string]interface{}{"error": err.Error(), "restore_certificate.certificate_id": restoreID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	response, err := azurePostDataV2WithRetry(ctx, id, client, azureCertificatesEndpoint+"/"+restoreID+"/restore", payloadJSON)
	if err != nil {
		details := utils.ApiError("Error restoring Azure certificate.",
			map[string]interface{}{"error": err.Error(), "restore_certificate.certificate_id": restoreID, "vault_id": vaultID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	client.Log.Debug("[azure_certificate_ops.go -> Restore][response:" + redactAzureCertResponse(response) + "]")
	if gjson.Get(response, "id").String() == "" {
		details := utils.ApiError("Error restoring Azure certificate, the response did not contain a certificate ID.",
			map[string]interface{}{"restore_certificate.certificate_id": restoreID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// findAzureCertificate returns the latest version of a certificate in a vault as JSON, or "" when none exists.
func findAzureCertificate(ctx context.Context, id string, client *common.Client, vaultID string, name string, diags *diag.Diagnostics) string {
	filters := url.Values{}
	filters.Set("cert_name", name)
	filters.Set("key_vault_id", vaultID)
	filters.Set("version", "-1")
	response, err := client.ListWithFilters(ctx, id, azureCertificatesEndpoint, filters)
	if err != nil {
		details := utils.ApiError("Error creating Azure certificate, failed to list certificates.",
			map[string]interface{}{"error": err.Error(), "name": name, "vault_id": vaultID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return gjson.Get(response, "resources.0").Raw
}

// getAzureCertificate fetches an Azure certificate by its CipherTrust Manager ID.
// If the certificate is not found (404):
//   - opLabel "deleting": warning added, "" returned - resource will be removed from state.
//   - any other opLabel: error added, "" returned - state is preserved.
//
// A non-404 error is always a hard error. "" is returned.
func getAzureCertificate(ctx context.Context, id string, client *common.Client, certID string, opLabel string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[azure_certificate_ops.go -> getAzureCertificate][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[azure_certificate_ops.go -> getAzureCertificate][" + id + "]")

	response, err := client.GetById(ctx, id, certID, azureCertificatesEndpoint)
	if err == nil {
		client.Log.Trace("[azure_certificate_ops.go -> Get][response:" + redactAzureCertResponse(response) + "]")
		return response
	}
	if strings.Contains(err.Error(), notFoundError) {
		if opLabel == "deleting" {
			msg := "Azure certificate was not found. It will be removed from state."
			details := utils.ApiError(msg, map[string]interface{}{"certificate_id": certID})
			client.Log.Warn(details)
			diags.AddWarning(details, "")
			return ""
		}
		msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "Azure certificate")
		details := utils.ApiError(msg, map[string]interface{}{"certificate_id": certID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	details := utils.ApiError("Error "+opLabel+" Azure certificate, failed to read Azure certificate.",
		map[string]interface{}{"error": err.Error(), "certificate_id": certID})
	client.Log.Error(details)
	diags.AddError(details, "")
	return ""
}

// waitForAzureCertificate polls the certificate until it is AVAILABLE. It fails when the certificate
// reports failed, the operation times out or ctx is canceled.
func waitForAzureCertificate(ctx context.Context, id string, client *common.Client, certID string, diags *diag.Diagnostics) string {
	// The provider operation timeout is used, or the default when it is not set.
	timeout := client.CCKMConfig.AzureOperationTimeout
	if timeout <= 0 {
		timeout = azureDefaultOperationTimeout
	}
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		response, err := client.GetById(ctx, id, certID, azureCertificatesEndpoint)
		if err != nil {
			details := utils.ApiError("Error creating Azure certificate, failed to read the certificate.",
				map[string]interface{}{"error": err.Error(), "certificate_id": certID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return ""
		}
		status := gjson.Get(response, "status").String()
		if status == azureCertificateAvailable {
			return response
		}
		if status == azureCertificateFailed {
			details := utils.ApiError("Error creating Azure certificate, the operation failed.",
				map[string]interface{}{"operation_error": gjson.Get(response, "operation_error").String(), "certificate_id": certID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return ""
		}
		if time.Now().After(deadline) {
			details := utils.ApiError("Error creating Azure certificate, timed out waiting for it to become available.",
				map[string]interface{}{"status": status, "certificate_id": certID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return ""
		}
		timer := time.NewTimer(azureCertificatePollSeconds * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			details := utils.ApiError("Error creating Azure certificate, the operation was cancelled.",
				map[string]interface{}{"error": ctx.Err().Error(), "certificate_id": certID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return ""
		case <-timer.C:
		}
	}
}

// redactAzureCertResponse returns a safe-to-log version of an Azure certificate API response.
func redactAzureCertResponse(response string) string {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(response), &data); err != nil {
		return response
	}
	for _, field := range []string{"azure_vault_id", "subscription_id", "tenant", "key_vault"} {
		if _, ok := data[field]; ok {
			data[field] = "redacted"
		}
	}
	if azureParam, ok := data["azure_param"].(map[string]interface{}); ok {
		if _, ok := azureParam["subject"]; ok {
			azureParam["subject"] = "redacted"
		}
		if _, ok := azureParam["tags"]; ok {
			azureParam["tags"] = "redacted"
		}
		if sans, ok := azureParam["sans"].(map[string]interface{}); ok {
			if _, ok := sans["emails"]; ok {
				sans["emails"] = "redacted"
			}
			if _, ok := sans["upns"]; ok {
				sans["upns"] = "redacted"
			}
			if _, ok := sans["dns_names"]; ok {
				sans["dns_names"] = "redacted"
			}
		}
		if policy, ok := azureParam["policy"].(map[string]interface{}); ok {
			if _, ok := policy["tags"]; ok {
				policy["tags"] = "redacted"
			}
			if x509Props, ok := policy["x509_props"].(map[string]interface{}); ok {
				if _, ok := x509Props["subject"]; ok {
					x509Props["subject"] = "redacted"
				}
				if sans, ok := x509Props["sans"].(map[string]interface{}); ok {
					if _, ok := sans["emails"]; ok {
						sans["emails"] = "redacted"
					}
					if _, ok := sans["upns"]; ok {
						sans["upns"] = "redacted"
					}
					if _, ok := sans["dns_names"]; ok {
						sans["dns_names"] = "redacted"
					}
				}
			}
		}
	}
	b, err := json.Marshal(data)
	if err != nil {
		return response
	}
	return string(b)
}
