package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/tidwall/gjson"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &resourceCMKey{}
	_ resource.ResourceWithConfigure   = &resourceCMKey{}
	_ resource.ResourceWithImportState = &resourceCMKey{}
)

func NewResourceCMKey() resource.Resource {
	return &resourceCMKey{}
}

type resourceCMKey struct {
	client *common.Client
}

func (r *resourceCMKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_key"
}

// Schema defines the schema for the resource.
func (r *resourceCMKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"template_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of a key template to apply during creation. On CDSPaaS, Restricted Key Users must use a template and may only supply owner_id in meta.",
			},
			"activation_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time the object becomes active",
			},
			"algorithm": schema.StringAttribute{
				Optional:    true,
				Description: "Cryptographic algorithm this key is used with. Defaults to 'aes'. Immutable after creation.",
				PlanModifiers: []planmodifier.String{
					StringImmutableModifier{FieldName: "algorithm"},
				},
				Validators: []validator.String{
					// The API accepts both lowercase (swagger POST enum) and uppercase
					// (returned by GET). Accept both cases for all algorithms so that
					// existing configs and test fixtures are not broken.
					stringvalidator.OneOf([]string{
						"aes", "tdes", "rsa", "ec",
						"hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512",
						"seed", "aria", "opaque",
						"AES", "TDES", "RSA", "EC",
						"HMAC-SHA1", "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512",
						"SEED", "ARIA", "OPAQUE",
					}...),
				},
			},
			"aliases": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Aliases associated with the key. The alias and alias-type must be specified. The alias index is assigned by this operation, and need not be specified.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"alias": schema.StringAttribute{
							Required:    true,
							Description: "An alias for a key name.",
						},
						"index": schema.StringAttribute{
							Computed:    true,
							Description: "Index assigned by the server. Read-only.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"type": schema.StringAttribute{
							Optional:    true,
							Description: "Type of alias (allowed values are string and uri).",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"string",
									"uri"}...),
							},
						},
					},
				},
			},
			"archive_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time the object becomes archived",
			},
			"assign_self_as_owner": schema.BoolAttribute{
				Optional:    true,
				Description: "If set to true, the user who is creating the key is set as the key owner. Specify either assignSelfAsOwner or ownerId in the meta, not both. Specifying both in the meta returns an error.",
			},
			"cert_type": schema.StringAttribute{
				Optional:    true,
				Description: "This specifies the type of certificate object that is being created. Valid values are 'x509-pem' and 'x509-der'. At present, we only support x.509 certificates. The cerfificate data is passed in via the 'material' field. The certificate type is infered from the material if it is left blank.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"x509-pem",
						"x509-der"}...),
				},
			},
			"compromise_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time the object entered into the compromised state.",
			},
			"compromise_occurrence_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time when the object was first believed to be compromised, if known. Only valid if the revocation reason is CACompromise or KeyCompromise, otherwise ignored.",
			},
			"curveid": schema.StringAttribute{
				Optional:    true,
				Description: "Cryptographic curve id for elliptic key. Key algorithm must be 'EC'. Immutable after creation.",
				PlanModifiers: []planmodifier.String{
					StringImmutableModifier{FieldName: "curveid"},
				},
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"secp224k1",
						"secp224r1",
						"secp256k1",
						"secp384r1",
						"secp521r1",
						"prime256v1",
						"brainpoolP224r1",
						"brainpoolP224t1",
						"brainpoolP256r1",
						"brainpoolP256t1",
						"brainpoolP384r1",
						"brainpoolP384t1",
						"brainpoolP512r1",
						"brainpoolP512t1",
						"curve25519"}...),
				},
			},
			"deactivation_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time the object becomes inactive",
			},
			"default_iv": schema.StringAttribute{
				Optional:    true,
				Description: "Deprecated. This field was introduced to support specific legacy integrations and applications. New applications are strongly recommended to use a unique IV for each encryption request. Refer to Crypto encrypt endpoint for more details. Must be a 16 byte hex encoded string (32 characters long). If specified, this will be set as the default IV for this key.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "It store information about key",
			},
			"destroy_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time the object was destroyed.",
			},
			"empty_material": schema.BoolAttribute{
				Optional:    true,
				Description: "If set to true, the key material is not created and left empty.",
			},
			"encoding": schema.StringAttribute{
				Optional:    true,
				Description: "Specifies the encoding used for the 'material' field.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"hex",
						"base64"}...),
				},
			},
			"format": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter is used while importing keys ('material' is not empty), and also when returning the key material after the key is created ('includeMaterial' is true).\nFor Asymmetric keys: When this parameter is not specified, while importing keys, the format of the material is inferred from the material itself. When this parameter is specified, while importing keys, the only allowed format is 'pkcs12', and this only applies to the 'rsa' algorithm (the 'material' should contain the base64 encoded value of the PFX file in this case).\nWhen returning the key material, this parameter specifies the format of the returned key material.\nOptions are pkcs1, pkcs8 (default), pkcs12\nFor Symmetric keys: When importing keys if specified, the value must be given according to the format of the material.\nWhen returning the key material, this parameter specifies the format of the returned key material. Options are raw or opaque",
			},
			"generate_key_id": schema.BoolAttribute{
				Optional:    true,
				Description: "If specified as true, the key's keyId identifier of type long is generated. Defaults to false.",
			},
			"hkdf_create_parameters": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Information which is used to create a Key using HKDF.",
				Attributes: map[string]schema.Attribute{
					"hash_algorithm": schema.StringAttribute{
						Optional:    true,
						Description: "Hash Algorithm is used for HKDF. This is required if ikmKeyName is specified, default is hmac-sha256.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"hmac-sha1",
								"hmac-sha224",
								"hmac-sha256",
								"hmac-sha384",
								"hmac-sha512"}...),
						},
					},
					"ikm_key_name": schema.StringAttribute{
						Optional:    true,
						Description: "Any existing symmetric key. Mandatory while using HKDF key generation.",
					},
					"info": schema.StringAttribute{
						Optional:    true,
						Description: "Info is an optional hex value for HKDF based derivation.",
					},
					"salt": schema.StringAttribute{
						Optional:    true,
						Description: "Salt is an optional hex value for HKDF based derivation.",
					},
				},
			},
			"id_size": schema.Int64Attribute{
				Optional:    true,
				Description: "Size of the ID for the key",
			},
			"key_id": schema.StringAttribute{
				Optional:    true,
				Description: "Additional identifier of the key. The format of this value is of type long. This is optional and applicable for import key only. If set, the value is imported as the key's keyId.",
			},
			"mac_sign_bytes": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the MAC/Signature bytes to be used for verification while importing a key. The wrappingMethod should be mac/sign and the required parameters for the verification must be set.",
			},
			"mac_sign_key_identifier": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the identifier of the key to be used for generating MAC or signature of the key material. The wrappingMethod should be mac/sign to verify the MAC/signature(macSignBytes) of the key material(material). For verifying the MAC, the key has to be a HMAC key. For verifying the signature, the key has to be an RSA private or public key.",
			},
			"mac_sign_key_identifier_type": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the identifier of the key(macSignKeyIdentifier) used for generating MAC or signature of the key material. The wrappingMethod should be mac/sign to verify the mac/signature(macSignBytes) of the key material(material).",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"name",
						"id",
						"alias"}...),
				},
			},
			"material": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				PlanModifiers: []planmodifier.String{
					StringImmutableModifier{FieldName: "material"},
				},
				Description: "If set, the value will be imported as the key's material. If not set, new key material will be generated on the server (certificate objects must always specify the material). The format of this value depends on the algorithm. If the algorithm is 'aes', 'tdes', 'hmac-*', 'seed' or 'aria', the value should be the hex-encoded bytes of the key material. If the algorithm is 'rsa', and the format is 'pkcs12', it should be the base64 encoded PFX file. If the algorithm is 'rsa' or 'ec', and format is not 'pkcs12', the value should be a PEM-encoded private or public key using PKCS1 or PKCS8 format. For a X.509 DER encoded certificate, certType equals 'x509-der' and the material should equal the hex encoded certificate. The material for a X.509 PEM encoded certificate (certType = 'x509-pem') should equal the certificate itself. When placing the PEM encoded certificate inside a JSON object (as in the playground), be sure to change all new line characters in the certificate to the string '\\n'.",
			},
			"muid": schema.StringAttribute{
				Optional:    true,
				Description: "Additional identifier of the key. This is optional and applicable for import key only. If set, the value is imported as the key's muid.",
			},
			"object_type": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					StringImmutableModifier{FieldName: "object_type"},
				},
				Description: "This specifies the type of object that is being created. Valid values are 'Symmetric Key', 'Public Key', 'Private Key', 'Secret Data', 'Opaque Object', or 'Certificate'. The object type is inferred for many objects, but must be supplied for the certificate object.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"Symmetric Key",
						"Public Key",
						"Private Key",
						"Secret Data",
						"Opaque Object",
						"Certificate"}...),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Optional friendly name, The key name should not contain special characters such as angular brackets (<,>) and backslash (\\).",
				PlanModifiers: []planmodifier.String{
					NameImmutableModifier{},
				},
			},
			"meta": schema.SingleNestedAttribute{
				Optional: true,
				Description: "Optional end-user or service data stored with the key. " +
					"PATCH merges JSON objects: removing a field from config does NOT clear it on the server. " +
					"On CDSPaaS, non-admin users must supply owner_id; Restricted Key Users may only supply owner_id.",
				Attributes: map[string]schema.Attribute{
					"owner_id": schema.StringAttribute{
						Optional:    true,
						Description: "Optional owner information for the key, required for non-admin unless 'assign_self_as_owner' is set to true. Value should be the user's user_id",
					},
					"permissions": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Key permissions",
						Attributes: map[string]schema.Attribute{
							"decrypt_with_key": schema.ListAttribute{
								Optional:    true,
								ElementType: types.StringType,
							},
							"encrypt_with_key": schema.ListAttribute{
								Optional:    true,
								ElementType: types.StringType,
							},
							"export_key": schema.ListAttribute{
								Optional:    true,
								ElementType: types.StringType,
							},
							"mac_verify_with_key": schema.ListAttribute{
								Optional:    true,
								ElementType: types.StringType,
							},
							"mac_with_key": schema.ListAttribute{
								Optional:    true,
								ElementType: types.StringType,
							},
							"read_key": schema.ListAttribute{
								Optional:    true,
								ElementType: types.StringType,
							},
							"sign_verify_with_key": schema.ListAttribute{
								Optional:    true,
								ElementType: types.StringType,
							},
							"sign_with_key": schema.ListAttribute{
								Optional:    true,
								ElementType: types.StringType,
							},
							"use_key": schema.ListAttribute{
								Optional:    true,
								ElementType: types.StringType,
							},
						},
					},
					"cte": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "CTE specific attributes",
						Attributes: map[string]schema.Attribute{
							"persistent_on_client": schema.BoolAttribute{
								Optional: true,
							},
							"encryption_mode": schema.StringAttribute{
								Optional: true,
							},
							"cte_versioned": schema.BoolAttribute{
								Optional: true,
							},
						},
					},
				},
			},
			"padded": schema.BoolAttribute{
				Optional:    true,
				Description: "This parameter determines the padding for the wrap algorithm while unwrapping a symmetric key,\nif wrappingMethod is encrypt and the wrappingEncryptionAlgo doesn't have a mode set\nif wrappingMethod is pbe.\nIf true, the RFC 5649(AES Key Wrap with Padding) is followed and if false, RFC 3394(AES Key Wrap) is followed for unwrapping the material for the symmetric key.\nIf a certificate is being unwrapped with the wrappingMethod set to encrypt, the padded parameter has to be set to true. This parameter defaults to false.",
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "For pkcs12 format, either password or secretDataLink should be specified. This should be the base64 encoded value of the password.",
			},
			"process_start_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time when a Managed Symmetric Key Object MAY begin to be used to process cryptographically protected information (e.g., decryption or unwrapping)",
			},
			"protect_stop_date": schema.StringAttribute{
				Optional:    true,
				Description: "Date/time after which a Managed Symmetric Key Object SHALL NOT be used for applying cryptographic protection (e.g., encryption or wrapping)",
			},
			"revocation_reason": schema.StringAttribute{
				Optional:    true,
				Description: "The reason the key is being revoked.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"Unspecified",
						"KeyCompromise",
						"CACompromise",
						"AffiliationChanged",
						"Superseded",
						"CessationOfOperation",
						"PrivilegeWithdrawn"}...),
				},
			},
			"revocation_message": schema.StringAttribute{
				Optional:    true,
				Description: "Message explaining revocation.",
			},
			"rotation_frequency_days": schema.StringAttribute{
				Optional:    true,
				Description: "Number of days from current date to rotate the key. It should be greater than or equal to 0. Default is an empty string. If set to 0, rotationFrequencyDays set to an empty string and auto rotation of key will be disabled.",
			},
			"secret_data_encoding": schema.StringAttribute{
				Optional:    true,
				Description: "For pkcs12 format, this field specifies the encoding method used for the secretDataLink material. Ignore this field if secretData is created from REST and is in plain format. Specify the value of this field as HEX format if secretData is created from KMIP.",
			},
			"secret_data_link": schema.StringAttribute{
				Optional:    true,
				Description: "For pkcs12 format, either secretDataLink or password should be specified. The value can be either ID or name of Secret Data.",
			},
			"signing_algo": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the algorithm to be used for generating the signature for the verification of the macSignBytes during import of key material. The wrappingMethod should be mac/sign to verify the signature(macSignBytes) of the key material(material).",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"RSA",
						"RSA-PSS"}...),
				},
			},
			"key_size": schema.Int64Attribute{
				Optional: true,
				PlanModifiers: []planmodifier.Int64{
					Int64ImmutableModifier{FieldName: "key_size"},
				},
				Description: "Bit length for the key. Immutable after creation.",
			},
			"unexportable": schema.BoolAttribute{
				Optional:    true,
				Description: "Key is not exportable. Defaults to false.",
			},
			"undeletable": schema.BoolAttribute{
				Optional:    true,
				Description: "Key is not deletable. Defaults to false.",
			},
			"state": schema.StringAttribute{
				Optional:    true,
				Description: "Optional initial key state (Pre-Active) upon creation. Defaults to Active. If set, activationDate and processStartDate can not be specified during key creation. In case of import, allowed values are Pre-Active, Active, Deactivated, Destroyed, Compromised and Destroyed Compromised. If key material is not specified, it will not be autogenerated if input parameters correspond to either of these states - Deactivated, Destroyed, Compromised and Destroyed Compromised. Key in Destroyed or Destroyed Compromised state would not have key material even if specified during key creation.",
			},
			"usage_mask": schema.Int64Attribute{
				Optional:    true,
				Description: "Cryptographic usage mask. Add the usage masks to allow certain usages. Sign (1), Verify (2), Encrypt (4), Decrypt (8), Wrap Key (16), Unwrap Key (32), Export (64), MAC Generate (128), MAC Verify (256), Derive Key (512), Content Commitment (1024), Key Agreement (2048), Certificate Sign (4096), CRL Sign (8192), Generate Cryptogram (16384), Validate Cryptogram (32768), Translate Encrypt (65536), Translate Decrypt (131072), Translate Wrap (262144), Translate Unwrap (524288), FPE Encrypt (1048576), FPE Decrypt (2097152). Add the usage mask values to allow the usages. To set all usage mask bits, use 4194303. Equivalent usageMask values for deprecated usages 'fpe' (FPE Encrypt + FPE Decrypt = 3145728), 'blob' (Encrypt + Decrypt = 12), 'hmac' (MAC Generate + MAC Verify = 384), 'encrypt' (Encrypt + Decrypt = 12), 'sign' (Sign + Verify = 3), 'any' (4194303 - all usage masks).",
			},
			"uuid": schema.StringAttribute{
				Optional:    true,
				Description: "Additional identifier of the key. The format of this value is 32 hexadecimal lowercase digits with 4 dashes. This is optional and applicable for import key only.\nIf set, the value is imported as the key's uuid.\nIf not set, new key uuid is generated on the server.",
			},
			"wrap_key_id_type": schema.StringAttribute{
				Optional:    true,
				Description: "IDType specifies how the wrapKeyName should be interpreted.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"name",
						"id",
						"alias"}...),
				},
			},
			"wrap_key_name": schema.StringAttribute{
				Optional:    true,
				Description: "While creating a new key, If 'includeMaterial' is true, then only the key material will be wrapped with material of the specified key name. The response material property will be the base64 encoded ciphertext. For more details, view wrapKeyName in export parameters.\nWhile importing a key, the key material will be unwrapped with material of the specified key name. The only applicable wrappingMethod for the unwrapping is encrypt and the wrapping key has to be an AES key or an RSA private key.",
			},
			"wrap_public_key": schema.StringAttribute{
				Optional:    true,
				Description: "If the algorithm is 'aes','tdes','hmac-*', 'seed' or 'aria', this value will be used to encrypt the returned key material. This value is ignored for other algorithms. Value must be an RSA public key, PEM-encoded public key in either PKCS1 or PKCS8 format, or a PEM-encoded X.509 certificate. If set, the returned 'material' value will be a Base64 encoded PKCS#1 v1.5 encrypted key. View wrapPublicKey in export parameters for more information. Only applicable if 'includeMaterial' is true.",
			},
			"wrap_public_key_padding": schema.StringAttribute{
				Optional:    true,
				Description: "WrapPublicKeyPadding specifies the type of padding scheme that needs to be set when importing the Key using the specified wrapkey. Accepted values are pkcs1, oaep, oaep256, oaep384, oaep512, and will default to pkcs1 when 'wrapPublicKeyPadding' is not set and 'WrapPublicKey' is set.\nWhile creating a new key, wrapPublicKeyPadding parameter should be specified only if 'includeMaterial' is true. In this case, key will get created and in response wrapped material using specified wrapPublicKeyPadding and other wrap parameters will be returned.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"pkcs1",
						"oaep",
						"oaep256",
						"oaep384",
						"oaep512"}...),
				},
			},
			"wrapping_encryption_algo": schema.StringAttribute{
				Optional:    true,
				Description: "It indicates the Encryption Algorithm information for wrapping the key. Format is : Algorithm/Mode/Padding. For example : AES/AESKEYWRAP. Here AES is Algorithm, AESKEYWRAP is Mode & Padding is not specified. AES/AESKEYWRAP is RFC-3394 & AES/AESKEYWRAPPADDING is RFC-5649. For wrapping private key, only AES/AESKEYWRAPPADDING is allowed. RSA/RSAAESKEYWRAPPADDING is used to wrap/unwrap asymmetric keys using RSA AES KWP method. Refer WrapRSAAES to provide optional parameters.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"AES/AESKEYWRAP",
						"AES/AESKEYWRAPPADDING",
						"RSA/RSAAESKEYWRAPPADDING"}...),
				},
			},
			"wrapping_hash_algo": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the hashing algorithm used if wrappingMethod corresponds to mac/sign. In case of MAC operation, the hashing algorithm used will be inferred from the type of HMAC key(macSignKeyIdentifier).",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"sha1",
						"sha224",
						"sha256",
						"sha384",
						"sha512"}...),
				},
			},
			"wrapping_method": schema.StringAttribute{
				Optional:    true,
				Description: "This parameter specifies the wrapping method used to wrap/mac/sign the key material",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"encrypt",
						"mac/sign",
						"pbe"}...),
				},
			},
			"xts": schema.BoolAttribute{
				Optional:    true,
				Description: "If set to true, then key created will be XTS/CBC-CS1 Key. Defaults to false. Key algorithm must be 'AES'.",
			},
			"public_key_parameters": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Information needed to create a public key.",
				Attributes: map[string]schema.Attribute{
					"activation_date": schema.StringAttribute{
						Optional:    true,
						Description: "Date/time the object becomes active",
					},
					"archive_date": schema.StringAttribute{
						Optional:    true,
						Description: "Date/time the object becomes archived",
					},
					"deactivation_date": schema.StringAttribute{
						Optional:    true,
						Description: "Date/time the object becomes inactive",
					},
					"name": schema.StringAttribute{
						Optional:    true,
						Description: "Friendly name of the corresponding public key",
					},
					"state": schema.StringAttribute{
						Optional:    true,
						Description: "Optional initial key state (Pre-Active) upon creation. If set, activationDate and processStartDate can not be specified during key creation. Defaults to Active.",
					},
					"undeletable": schema.BoolAttribute{
						Optional:    true,
						Description: "Key is not deletable. Defaults to false.",
					},
					"unexportable": schema.BoolAttribute{
						Optional:    true,
						Description: "Key is not exportable. Defaults to false.",
					},
					"usage_mask": schema.Int64Attribute{
						Optional:    true,
						Description: "Defined in PostKey parameters",
					},
					"aliases": schema.ListNestedAttribute{
						Optional:    true,
						Description: "",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"alias": schema.StringAttribute{
									Required:    true,
									Description: "An alias for a key name.",
								},
								"index": schema.StringAttribute{
									Computed:    true,
									Description: "Index assigned by the server. Read-only.",
									PlanModifiers: []planmodifier.String{
										stringplanmodifier.UseStateForUnknown(),
									},
								},
								"type": schema.StringAttribute{
									Required:    true,
									Description: "Type of alias (allowed values are string and uri).",
									Validators: []validator.String{
										stringvalidator.OneOf([]string{"string",
											"uri"}...),
									},
								},
							},
						},
					},
				},
			},
			"remove_from_state_on_destroy": schema.BoolAttribute{
				Optional:    true,
				Description: "This parameter only applies to keys that are 'undeleteable'. If this parameter is true the key will be removed from terraform state during the terraform destroy process. It can not be deleted from CipherTrust Manager while 'undeleteable' is true. Default is 'false'.",
			},
			"wrap_hkdf": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Information which is used to wrap a Key using HKDF.",
				Attributes: map[string]schema.Attribute{
					"hash_algorithm": schema.StringAttribute{
						Optional:    true,
						Description: "Hash Algorithm is used for HKDF Wrapping.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"hmac-sha1",
								"hmac-sha224",
								"hmac-sha256",
								"hmac-sha384",
								"hmac-sha512"}...),
						},
					},
					"okm_len": schema.Int64Attribute{
						Optional:    true,
						Description: "The desired output key material length in integer.",
					},
					"info": schema.StringAttribute{
						Optional:    true,
						Description: "Info is an optional hex value for HKDF based derivation.",
					},
					"salt": schema.StringAttribute{
						Optional:    true,
						Description: "Salt is an optional hex value for HKDF based derivation.",
					},
				},
			},
			"wrap_pbe": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "WrapPBE derives the key from the password and other parameters such as salt, iteration count, hashing algorithm, and derived key-length. PBE currently supports wrapping of symmetric keys (AES), private keys, and certificates. WrapPBE is a two-step process to export a key as mentioned below. The key import is similar to the key export but it unwraps the target key in the second step. Step 1 Use PBKDF2 with the specified parameters (pwd, hash-function, salt, iterations, purpose (opt), KEK length) to derive the KEK. For more details, refer to RFC 2898. Step 2 Perform AES-KW/KWP to wrap the target key using the KEK derived from Step 1. The AES KEK size is calculated by the KEK length parameter as described in Step 1. For more details, refer to RFC 3394 and 5649.",
				Attributes: map[string]schema.Attribute{
					"dklen": schema.Int64Attribute{
						Optional:    true,
						Description: "Intended length in octets of the derived key. dklen must be in range of 14 bytes to 512 bytes.",
					},
					"hash_algorithm": schema.StringAttribute{
						Optional:    true,
						Description: "Underlying hashing algorithm that acts as a pseudorandom function to generate derive keys.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"hmac-sha1",
								"hmac-sha224",
								"hmac-sha256",
								"hmac-sha384",
								"hmac-sha512",
								"hmac-sha512/224",
								"hmac-sha512/256",
								"hmac-sha3-224",
								"hmac-sha3-256",
								"hmac-sha3-384",
								"hmac-sha3-512"}...),
						},
					},
					"salt": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "A Hex encoded string. pbeSalt must be in range of 16 bytes to 512 bytes.",
						Validators: []validator.String{
							stringvalidator.LengthBetween(16, 512),
						},
					},
					"iteration": schema.Int64Attribute{
						Optional:    true,
						Description: "Iteration count increase the cost of producing keys from a password. Iteration must be in range of 1 to 1,00,00,000.",
						Validators: []validator.Int64{
							int64validator.Between(1, 10000000),
						},
					},
					"password": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "Base password to generate derive keys. It cannot be used in conjunction with passwordidentifier. password must be in range of 8 bytes to 128 bytes.",
						Validators: []validator.String{
							stringvalidator.LengthBetween(8, 128),
						},
					},
					"password_identifier": schema.StringAttribute{
						Optional:    true,
						Description: "Secret password identifier for password. It cannot be used in conjunction with password.",
					},
					"password_identifier_type": schema.StringAttribute{
						Optional:    true,
						Description: "Type of the Passwordidentifier. If not set then default value is name.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"id",
								"name",
								"slug"}...),
						},
						//Default: stringdefault.StaticString("name"),
					},
					"purpose": schema.StringAttribute{
						Optional:    true,
						Description: "User defined purpose. If specified will be prefixed to pbeSalt. pbePurpose must not be greater than 128 bytes.",
					},
				},
			},
			"wrap_rsaaes": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Parameters for wrapping a key using RSA AES Key Wrap Padding (RSA/RSAAESKEYWRAPPADDING).",
				Attributes: map[string]schema.Attribute{
					"aes_key_size": schema.Int64Attribute{
						Optional:    true,
						Description: "Size of AES key for RSA AES KWP. Accepted value are 128, 192, 256. Default value is 256.",
						Validators: []validator.Int64{
							int64validator.OneOf([]int64{128,
								192,
								256}...),
						},
						//Default: int64default.StaticInt64(256),
					},
					"padding": schema.StringAttribute{
						Optional:    true,
						Description: "Padding specifies the type of padding scheme that needs to be set when exporting the Key using RSA AES wrap.",
						Validators: []validator.String{
							stringvalidator.OneOf([]string{"oaep",
								"oaep256",
								"oaep384",
								"oaep512"}...),
						},
						//Default: stringdefault.StaticString("oaep256"),
					},
				},
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional map of string key-value labels to associate with the key.",
			},
			"all_versions": schema.BoolAttribute{
				Optional: true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_key.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMKeyTFSDK
	var payload CMKeyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ActivationDate.ValueString() != "" {
		payload.ActivationDate = plan.ActivationDate.ValueString()
	}
	if plan.Algorithm.ValueString() != "" {
		payload.Algorithm = plan.Algorithm.ValueString()
	}
	if plan.ArchiveDate.ValueString() != "" {
		payload.ArchiveDate = plan.ArchiveDate.ValueString()
	}
	if !plan.AssignSelfAsOwner.IsNull() && !plan.AssignSelfAsOwner.IsUnknown() {
		payload.AssignSelfAsOwner = plan.AssignSelfAsOwner.ValueBool()
	}
	if plan.CertType.ValueString() != "" {
		payload.CertType = plan.CertType.ValueString()
	}
	if plan.CompromiseDate.ValueString() != "" {
		payload.CompromiseDate = plan.CompromiseDate.ValueString()
	}
	if plan.CompromiseOccurrenceDate.ValueString() != "" {
		payload.CompromiseOccurrenceDate = plan.CompromiseOccurrenceDate.ValueString()
	}
	if plan.Curveid.ValueString() != "" {
		payload.Curveid = plan.Curveid.ValueString()
	}
	if plan.DeactivationDate.ValueString() != "" {
		payload.DeactivationDate = plan.DeactivationDate.ValueString()
	}
	if plan.DefaultIV.ValueString() != "" {
		payload.DefaultIV = plan.DefaultIV.ValueString()
	}
	if plan.Description.ValueString() != "" {
		payload.Description = plan.Description.ValueString()
	}
	if plan.DestroyDate.ValueString() != "" {
		payload.DestroyDate = plan.DestroyDate.ValueString()
	}
	if !plan.EmptyMaterial.IsNull() && !plan.EmptyMaterial.IsUnknown() {
		payload.EmptyMaterial = plan.EmptyMaterial.ValueBool()
	}
	if plan.Encoding.ValueString() != "" {
		payload.Encoding = plan.Encoding.ValueString()
	}
	if plan.Format.ValueString() != "" {
		payload.Format = plan.Format.ValueString()
	}
	if !plan.GenerateKeyId.IsNull() && !plan.GenerateKeyId.IsUnknown() {
		payload.GenerateKeyId = plan.GenerateKeyId.ValueBool()
	}
	// if plan.ID.ValueString() != "" {
	// 	payload.ID = plan.ID.ValueString()
	// }
	if !plan.IDSize.IsNull() && !plan.IDSize.IsUnknown() {
		payload.IDSize = plan.IDSize.ValueInt64()
	}
	if plan.KeyId.ValueString() != "" {
		payload.KeyId = plan.KeyId.ValueString()
	}
	if plan.MacSignBytes.ValueString() != "" {
		payload.MacSignBytes = plan.MacSignBytes.ValueString()
	}
	if plan.MacSignKeyIdentifier.ValueString() != "" {
		payload.MacSignKeyIdentifier = plan.MacSignKeyIdentifier.ValueString()
	}
	if plan.MacSignKeyIdentifierType.ValueString() != "" {
		payload.MacSignKeyIdentifierType = plan.MacSignKeyIdentifierType.ValueString()
	}
	if plan.Material.ValueString() != "" {
		payload.Material = plan.Material.ValueString()
	}
	if plan.MUID.ValueString() != "" {
		payload.MUID = plan.MUID.ValueString()
	}
	if plan.Name.ValueString() != "" {
		payload.Name = plan.Name.ValueString()
	}
	if plan.ObjectType.ValueString() != "" {
		payload.ObjectType = plan.ObjectType.ValueString()
	}
	if !plan.Padded.IsNull() && !plan.Padded.IsUnknown() {
		payload.Padded = plan.Padded.ValueBool()
	}
	if plan.Password.ValueString() != "" {
		payload.Password = plan.Password.ValueString()
	}
	if plan.ProcessStartDate.ValueString() != "" {
		payload.ProcessStartDate = plan.ProcessStartDate.ValueString()
	}
	if plan.ProtectStopDate.ValueString() != "" {
		payload.ProtectStopDate = plan.ProtectStopDate.ValueString()
	}
	if plan.RevocationMessage.ValueString() != "" {
		payload.RevocationMessage = plan.RevocationMessage.ValueString()
	}
	if plan.RevocationReason.ValueString() != "" {
		payload.RevocationReason = plan.RevocationReason.ValueString()
	}
	if plan.RotationFrequencyDays.ValueString() != "" {
		payload.RotationFrequencyDays = plan.RotationFrequencyDays.ValueString()
	}
	if plan.SecretDataEncoding.ValueString() != "" {
		payload.SecretDataEncoding = plan.SecretDataEncoding.ValueString()
	}
	if plan.SecretDataLink.ValueString() != "" {
		payload.SecretDataLink = plan.SecretDataLink.ValueString()
	}
	if plan.SigningAlgo.ValueString() != "" {
		payload.SigningAlgo = plan.SigningAlgo.ValueString()
	}
	if !plan.Size.IsNull() && !plan.Size.IsUnknown() {
		payload.Size = plan.Size.ValueInt64()
	}
	if plan.State.ValueString() != "" {
		payload.State = plan.State.ValueString()
	}
	if plan.TemplateID.ValueString() != "" {
		payload.TemplateID = plan.TemplateID.ValueString()
	}
	if !plan.UnDeletable.IsNull() && !plan.UnDeletable.IsUnknown() {
		v := plan.UnDeletable.ValueBool()
		payload.UnDeletable = &v
	}
	if !plan.UnExportable.IsNull() && !plan.UnExportable.IsUnknown() {
		v := plan.UnExportable.ValueBool()
		payload.UnExportable = &v
	}
	if !plan.UsageMask.IsNull() && !plan.UsageMask.IsUnknown() {
		payload.UsageMask = plan.UsageMask.ValueInt64()
	}
	if plan.UUID.ValueString() != "" {
		payload.UUID = plan.UUID.ValueString()
	}
	if plan.WrapKeyIDType.ValueString() != "" {
		payload.WrapKeyIDType = plan.WrapKeyIDType.ValueString()
	}
	if plan.WrapKeyName.ValueString() != "" {
		payload.WrapKeyName = plan.WrapKeyName.ValueString()
	}
	if plan.WrapPublicKey.ValueString() != "" {
		payload.WrapPublicKey = plan.WrapPublicKey.ValueString()
	}
	if plan.WrapPublicKeyPadding.ValueString() != "" {
		payload.WrapPublicKeyPadding = plan.WrapPublicKeyPadding.ValueString()
	}
	if plan.WrappingEncryptionAlgo.ValueString() != "" {
		payload.WrappingEncryptionAlgo = plan.WrappingEncryptionAlgo.ValueString()
	}
	if plan.WrappingHashAlgo.ValueString() != "" {
		payload.WrappingHashAlgo = plan.WrappingHashAlgo.ValueString()
	}
	if plan.WrappingMethod.ValueString() != "" {
		payload.WrappingMethod = plan.WrappingMethod.ValueString()
	}
	if !plan.XTS.IsNull() && !plan.XTS.IsUnknown() {
		payload.XTS = plan.XTS.ValueBool()
	}
	// Add aliases to the payload if set
	var arrAlias []KeyAliasJSON
	for _, alias := range plan.Aliases {
		var aliasJSON KeyAliasJSON
		if alias.Alias.ValueString() != "" {
			aliasJSON.Alias = alias.Alias.ValueString()
		}
		// index is Computed-only (server-assigned); only send it if state already has one
		// (i.e. this is a re-create scenario where we know the prior index). On first Create
		// the index is always null, so we omit it and let the server assign.
		if alias.Index.ValueString() != "" {
			parsed, parseErr := strconv.ParseInt(alias.Index.ValueString(), 10, 64)
			if parseErr != nil {
				resp.Diagnostics.AddError("Error Creating CipherTrust Key", "Invalid alias index value: "+alias.Index.ValueString()+": "+parseErr.Error())
				return
			}
			aliasJSON.Index = &parsed
		}
		if alias.Type.ValueString() != "" {
			aliasJSON.Type = alias.Type.ValueString()
		}
		arrAlias = append(arrAlias, aliasJSON)
	}
	payload.Aliases = arrAlias
	// Add hkdfCreateParameters to payload if set
	var hkdfCreateParameters HKDFParametersJSON
	if plan.HKDFCreateParameters != nil {
		tflog.Debug(ctx, "HKDFParameters should not be empty at this point")
		if plan.HKDFCreateParameters.HashAlgorithm.ValueString() != "" {
			hkdfCreateParameters.HashAlgorithm = plan.HKDFCreateParameters.HashAlgorithm.ValueString()
		}
		if plan.HKDFCreateParameters.IKMKeyName.ValueString() != "" {
			hkdfCreateParameters.IKMKeyName = plan.HKDFCreateParameters.IKMKeyName.ValueString()
		}
		if plan.HKDFCreateParameters.Info.ValueString() != "" {
			hkdfCreateParameters.Info = plan.HKDFCreateParameters.Info.ValueString()
		}
		if plan.HKDFCreateParameters.Salt.ValueString() != "" {
			hkdfCreateParameters.Salt = plan.HKDFCreateParameters.Salt.ValueString()
		}
		payload.HKDFCreateParameters = &hkdfCreateParameters
	}
	// Add meta to payload if set
	var metadata KeyMetadataJSON
	if plan.Metadata != nil {
		if plan.Metadata.OwnerId.ValueString() != "" {
			metadata.OwnerId = plan.Metadata.OwnerId.ValueString()
		}
		if plan.Metadata.Permissions != nil {
			var permission KeyMetadataPermissionsJSON
			var decryptWithKey []string
			var encryptWithKey []string
			var exportKey []string
			var macVerifyWithKey []string
			var macWithKey []string
			var readKey []string
			var signVerifyWithKey []string
			var signWithKey []string
			var useKey []string

			for _, str := range plan.Metadata.Permissions.DecryptWithKey {
				decryptWithKey = append(decryptWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.EncryptWithKey {
				encryptWithKey = append(encryptWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.ExportKey {
				exportKey = append(exportKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.MACVerifyWithKey {
				macVerifyWithKey = append(macVerifyWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.MACWithKey {
				macWithKey = append(macWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.ReadKey {
				readKey = append(readKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.SignVerifyWithKey {
				signVerifyWithKey = append(signVerifyWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.SignWithKey {
				signWithKey = append(signWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.UseKey {
				useKey = append(useKey, str.ValueString())
			}
			permission.DecryptWithKey = decryptWithKey
			permission.EncryptWithKey = encryptWithKey
			permission.ExportKey = exportKey
			permission.MACVerifyWithKey = macVerifyWithKey
			permission.MACWithKey = macWithKey
			permission.ReadKey = readKey
			permission.SignVerifyWithKey = signVerifyWithKey
			permission.SignWithKey = signWithKey
			permission.UseKey = useKey
			metadata.Permissions = &permission
		}
		if plan.Metadata.CTE != nil {
			var cteParams KeyMetadataCTEJSON
			if !plan.Metadata.CTE.PersistentOnClient.IsNull() && !plan.Metadata.CTE.PersistentOnClient.IsUnknown() {
				cteParams.PersistentOnClient = plan.Metadata.CTE.PersistentOnClient.ValueBool()
			}
			if plan.Metadata.CTE.EncryptionMode.ValueString() != "" {
				cteParams.EncryptionMode = plan.Metadata.CTE.EncryptionMode.ValueString()
			}
			if !plan.Metadata.CTE.CTEVersioned.IsNull() && !plan.Metadata.CTE.CTEVersioned.IsUnknown() {
				cteParams.CTEVersioned = plan.Metadata.CTE.CTEVersioned.ValueBool()
			}
			metadata.CTE = &cteParams
		}
		payload.Metadata = &metadata
	}

	// Add publicKeyParameters to payload if set
	var publicKeyParameters PublicKeyParametersJSON
	if plan.PublicKeyParameters != nil {
		if plan.PublicKeyParameters.ActivationDate.ValueString() != "" {
			publicKeyParameters.ActivationDate = plan.PublicKeyParameters.ActivationDate.ValueString()
		}
		if plan.PublicKeyParameters.ArchiveDate.ValueString() != "" {
			publicKeyParameters.ArchiveDate = plan.PublicKeyParameters.ArchiveDate.ValueString()
		}
		if plan.PublicKeyParameters.DeactivationDate.ValueString() != "" {
			publicKeyParameters.DeactivationDate = plan.PublicKeyParameters.DeactivationDate.ValueString()
		}
		if plan.PublicKeyParameters.Name.ValueString() != "" {
			publicKeyParameters.Name = plan.PublicKeyParameters.Name.ValueString()
		}
		if plan.PublicKeyParameters.State.ValueString() != "" {
			publicKeyParameters.State = plan.PublicKeyParameters.State.ValueString()
		}
		if !plan.PublicKeyParameters.UnDeletable.IsNull() && !plan.PublicKeyParameters.UnDeletable.IsUnknown() {
			publicKeyParameters.UnDeletable = plan.PublicKeyParameters.UnDeletable.ValueBool()
		}
		if !plan.PublicKeyParameters.UnExportable.IsNull() && !plan.PublicKeyParameters.UnExportable.IsUnknown() {
			publicKeyParameters.UnExportable = plan.PublicKeyParameters.UnExportable.ValueBool()
		}
		if !plan.PublicKeyParameters.UsageMask.IsNull() && !plan.PublicKeyParameters.UsageMask.IsUnknown() {
			publicKeyParameters.UsageMask = plan.PublicKeyParameters.UsageMask.ValueInt64()
		}
		var arrPubKeyAlias []KeyAliasJSON
		for _, pubKeyAlias := range plan.PublicKeyParameters.Aliases {
			var pubKeyAliasJSON KeyAliasJSON
			if pubKeyAlias.Alias.ValueString() != "" {
				pubKeyAliasJSON.Alias = pubKeyAlias.Alias.ValueString()
			}
			if pubKeyAlias.Index.ValueString() != "" {
				parsed, parseErr := strconv.ParseInt(pubKeyAlias.Index.ValueString(), 10, 64)
				if parseErr != nil {
					resp.Diagnostics.AddError("Error Creating CipherTrust Key", "Invalid public key alias index value: "+pubKeyAlias.Index.ValueString()+": "+parseErr.Error())
					return
				}
				pubKeyAliasJSON.Index = &parsed
			}
			if pubKeyAlias.Type.ValueString() != "" {
				pubKeyAliasJSON.Type = pubKeyAlias.Type.ValueString()
			}
			arrPubKeyAlias = append(arrPubKeyAlias, pubKeyAliasJSON)
		}
		publicKeyParameters.Aliases = arrPubKeyAlias
		payload.PublicKeyParameters = &publicKeyParameters
	}
	// Add wrapHKDF to payload if set
	var wrapHKDF WrapHKDFJSON
	if plan.HKDFWrap != nil {
		if plan.HKDFWrap.HashAlgorithm.ValueString() != "" {
			wrapHKDF.HashAlgorithm = plan.HKDFWrap.HashAlgorithm.ValueString()
		}
		if !plan.HKDFWrap.OKMLen.IsNull() && !plan.HKDFWrap.OKMLen.IsUnknown() {
			wrapHKDF.OKMLen = plan.HKDFWrap.OKMLen.ValueInt64()
		}
		if plan.HKDFWrap.Info.ValueString() != "" {
			wrapHKDF.Info = plan.HKDFWrap.Info.ValueString()
		}
		if plan.HKDFWrap.Salt.ValueString() != "" {
			wrapHKDF.Salt = plan.HKDFWrap.Salt.ValueString()
		}
		payload.HKDFWrap = &wrapHKDF
	}
	// Add wrapPBE to payload if set
	var wrapPBE WrapPBEJSON
	if plan.PBEWrap != nil {
		if !plan.PBEWrap.DKLen.IsNull() && !plan.PBEWrap.DKLen.IsUnknown() {
			wrapPBE.DKLen = plan.PBEWrap.DKLen.ValueInt64()
		}
		if plan.PBEWrap.HashAlgorithm.ValueString() != "" {
			wrapPBE.HashAlgorithm = plan.PBEWrap.HashAlgorithm.ValueString()
		}
		if !plan.PBEWrap.Iteration.IsNull() && !plan.PBEWrap.Iteration.IsUnknown() {
			wrapPBE.Iteration = plan.PBEWrap.Iteration.ValueInt64()
		}
		if plan.PBEWrap.Password.ValueString() != "" {
			wrapPBE.Password = plan.PBEWrap.Password.ValueString()
		}
		if plan.PBEWrap.PasswordIdentifier.ValueString() != "" {
			wrapPBE.PasswordIdentifier = plan.PBEWrap.PasswordIdentifier.ValueString()
		}
		if plan.PBEWrap.PasswordIdentifierType.ValueString() != "" {
			wrapPBE.PasswordIdentifierType = plan.PBEWrap.PasswordIdentifierType.ValueString()
		}
		if plan.PBEWrap.Purpose.ValueString() != "" {
			wrapPBE.Purpose = plan.PBEWrap.Purpose.ValueString()
		}
		if plan.PBEWrap.Salt.ValueString() != "" {
			wrapPBE.Salt = plan.PBEWrap.Salt.ValueString()
		}
		payload.PBEWrap = &wrapPBE
	}
	// Add wrapPBE to payload if set
	var wrapRSAAES WrapRSAAESJSON
	if plan.RSAAESWrap != nil {
		if !plan.RSAAESWrap.AESKeySize.IsNull() && !plan.RSAAESWrap.AESKeySize.IsUnknown() {
			wrapRSAAES.AESKeySize = plan.RSAAESWrap.AESKeySize.ValueInt64()
		}
		if plan.RSAAESWrap.Padding.ValueString() != "" {
			wrapRSAAES.Padding = plan.RSAAESWrap.Padding.ValueString()
		}
		payload.RSAAESWrap = &wrapRSAAES
	}
	// Add labels to payload
	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = labelsPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Key Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_KEY_MANAGEMENT, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating key on CipherTrust Manager: ",
			"Could not create key, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	// Hydrate boolean fields from POST response only when the server explicitly returns
	// them. If a field is absent from the response (the API omits false-default values,
	// and xts/unexportable/undeletable are not always echoed), preserve the plan value
	// that the user already set rather than overwriting with null.
	if !plan.UnDeletable.IsNull() {
		if r := gjson.Get(response, "undeletable"); r.Exists() {
			plan.UnDeletable = types.BoolValue(r.Bool())
		}
	}
	if !plan.UnExportable.IsNull() {
		if r := gjson.Get(response, "unexportable"); r.Exists() {
			plan.UnExportable = types.BoolValue(r.Bool())
		}
	}
	if !plan.XTS.IsNull() {
		// xts is not in the Key GET response schema; preserve plan value if absent.
		if r := gjson.Get(response, "xts"); r.Exists() {
			plan.XTS = types.BoolValue(r.Bool())
		}
	}

	// Hydrate aliases from POST response to pick up server-assigned indices.
	// Only hydrate if user configured aliases (plan.Aliases != nil).
	if plan.Aliases != nil {
		aliasesResp := gjson.Get(response, "aliases")
		if aliasesResp.Exists() && len(aliasesResp.Array()) > 0 {
			// Build ordered map: alias name → position in plan (for stable sort).
			planOrder := make(map[string]int, len(plan.Aliases))
			configured := make(map[string]bool, len(plan.Aliases))
			for i, ca := range plan.Aliases {
				planOrder[ca.Alias.ValueString()] = i
				configured[ca.Alias.ValueString()] = true
			}
			var hydratedAliases []*KeyAliasTFSDK
			for _, elem := range aliasesResp.Array() {
				if !configured[elem.Get("alias").String()] {
					continue
				}
				a := &KeyAliasTFSDK{}
				if r := elem.Get("alias"); r.Exists() {
					a.Alias = types.StringValue(r.String())
				} else {
					a.Alias = types.StringNull()
				}
				if r := elem.Get("index"); r.Exists() {
					a.Index = types.StringValue(r.String())
				} else {
					a.Index = types.StringNull()
				}
				if r := elem.Get("type"); r.Exists() {
					a.Type = types.StringValue(r.String())
				} else {
					a.Type = types.StringNull()
				}
				hydratedAliases = append(hydratedAliases, a)
			}
			if hydratedAliases != nil {
				// Sort to match the plan's alias order to avoid perpetual list diffs.
				sort.Slice(hydratedAliases, func(i, j int) bool {
					return planOrder[hydratedAliases[i].Alias.ValueString()] <
						planOrder[hydratedAliases[j].Alias.ValueString()]
				})
				plan.Aliases = hydratedAliases
			}
		}
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_key.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_key.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_key.go -> Read]["+id+"]")

	var state CMKeyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_KEY_MANAGEMENT)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust Key",
			"Could not read key "+state.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	plan := state

	// Computed-only — unconditional
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	// Unconditional Optional+Computed scalar fields
	if r := gjson.Get(response, "name"); r.Exists() {
		plan.Name = types.StringValue(r.String())
	} else {
		plan.Name = types.StringNull()
	}
	// algorithm: CM normalizes to uppercase ("AES") but existing configs use both
	// "aes" and "AES". When state is null (import passthrough), hydrate from server
	// and lowercase to match the typical config casing. Otherwise preserve state to
	// avoid perpetual casing drift.
	if state.Algorithm.IsNull() && state.Name.IsNull() {
		// Import path: state has only ID populated; hydrate algorithm from server.
		if r := gjson.Get(response, "algorithm"); r.Exists() {
			plan.Algorithm = types.StringValue(strings.ToLower(r.String()))
		}
	}
	// usage_mask is Optional only — hydrate only when the user configured it (state
	// non-null) to avoid perpetual drift for keys created without a usage_mask.
	if !state.UsageMask.IsNull() {
		if r := gjson.Get(response, "usageMask"); r.Exists() {
			plan.UsageMask = types.Int64Value(r.Int())
		} else {
			plan.UsageMask = types.Int64Null()
		}
	}
	// key_size: hydrate when user configured it (non-null) OR on import (name null).
	if !state.Size.IsNull() || state.Name.IsNull() {
		if r := gjson.Get(response, "size"); r.Exists() {
			plan.Size = types.Int64Value(r.Int())
		} else if !state.Size.IsNull() {
			plan.Size = types.Int64Null()
		}
	}
	// description: guard on state to prevent drift for keys created without a description.
	// CM returns "" for description-less keys; unconditional hydration turns null→"", causing a perpetual diff.
	if !state.Description.IsNull() {
		if r := gjson.Get(response, "description"); r.Exists() {
			plan.Description = types.StringValue(r.String())
		} else {
			plan.Description = types.StringNull()
		}
	}
	// rotation_frequency_days: guard on state to avoid drift for keys created without it.
	// API normalises "0" → "" (disabled). When server returns "" and prior state was "0",
	// preserve "0" in state so the user's config value survives the round-trip.
	if !state.RotationFrequencyDays.IsNull() {
		if r := gjson.Get(response, "rotationFrequencyDays"); r.Exists() {
			serverVal := r.String()
			if serverVal == "" && state.RotationFrequencyDays.ValueString() == "0" {
				plan.RotationFrequencyDays = state.RotationFrequencyDays
			} else {
				plan.RotationFrequencyDays = types.StringValue(serverVal)
			}
		} else {
			// Field absent from response means rotation is disabled (server treats as "").
			// Preserve "0" in state when user configured "0" to disable rotation, so the
			// round-trip "0" → absent does not cause a perpetual diff.
			if state.RotationFrequencyDays.ValueString() == "0" {
				plan.RotationFrequencyDays = state.RotationFrequencyDays
			} else {
				plan.RotationFrequencyDays = types.StringNull()
			}
		}
	}
	// Bug 2 fix — unconditional bool fields; when CM omits the field (false is the
	// API default and is returned by omission), preserve the prior state value to
	// Only hydrate undeletable/unexportable/xts from GET when the user explicitly
	// configured them (state non-null). CM returns false for unconfigured booleans;
	// hydrating unconditionally causes false→null drift for users who never set them.
	if !state.UnDeletable.IsNull() {
		if r := gjson.Get(response, "undeletable"); r.Exists() {
			plan.UnDeletable = types.BoolValue(r.Bool())
		}
		// else: API omits false-default value; preserve prior state (plan=state above)
	}
	if !state.UnExportable.IsNull() {
		if r := gjson.Get(response, "unexportable"); r.Exists() {
			plan.UnExportable = types.BoolValue(r.Bool())
		}
	}
	if !state.XTS.IsNull() {
		// xts is not in the Key GET response schema; preserve state value when absent.
		if r := gjson.Get(response, "xts"); r.Exists() {
			plan.XTS = types.BoolValue(r.Bool())
		}
	}

	// Server-auto-populated Optional+Computed — guard on IsNull to prevent drift for unconfigured fields
	if !state.State.IsNull() {
		if r := gjson.Get(response, "state"); r.Exists() {
			plan.State = types.StringValue(r.String())
		} else {
			plan.State = types.StringNull()
		}
	}
	if !state.UUID.IsNull() {
		if r := gjson.Get(response, "uuid"); r.Exists() {
			plan.UUID = types.StringValue(r.String())
		} else {
			plan.UUID = types.StringNull()
		}
	}
	if !state.MUID.IsNull() {
		if r := gjson.Get(response, "muid"); r.Exists() {
			plan.MUID = types.StringValue(r.String())
		} else {
			plan.MUID = types.StringNull()
		}
	}
	if !state.ObjectType.IsNull() {
		if r := gjson.Get(response, "objectType"); r.Exists() {
			plan.ObjectType = types.StringValue(r.String())
		} else {
			plan.ObjectType = types.StringNull()
		}
	}
	if !state.DefaultIV.IsNull() {
		if r := gjson.Get(response, "defaultIV"); r.Exists() {
			plan.DefaultIV = types.StringValue(r.String())
		} else {
			plan.DefaultIV = types.StringNull()
		}
	}
	if !state.ActivationDate.IsNull() {
		if r := gjson.Get(response, "activationDate"); r.Exists() {
			plan.ActivationDate = types.StringValue(r.String())
		} else {
			plan.ActivationDate = types.StringNull()
		}
	}
	if !state.DeactivationDate.IsNull() {
		if r := gjson.Get(response, "deactivationDate"); r.Exists() {
			plan.DeactivationDate = types.StringValue(r.String())
		} else {
			plan.DeactivationDate = types.StringNull()
		}
	}
	if !state.ArchiveDate.IsNull() {
		if r := gjson.Get(response, "archiveDate"); r.Exists() {
			plan.ArchiveDate = types.StringValue(r.String())
		} else {
			plan.ArchiveDate = types.StringNull()
		}
	}

	// Labels: only hydrate when the user explicitly configured labels (state non-null).
	// When state is null (labels never configured), keep null regardless of what the
	// server returns. This prevents server-auto-added internal labels (e.g.,
	// "ncryptify-reserved/composite-key") from appearing in state and causing drift.
	if !state.Labels.IsNull() {
		labelsResult := gjson.Get(response, "labels")
		if labelsResult.Exists() && labelsResult.Type != gjson.Null {
			m := make(map[string]string)
			for k, v := range labelsResult.Map() {
				m[k] = v.String()
			}
			if len(m) == 0 {
				plan.Labels = types.MapNull(types.StringType)
			} else {
				plan.Labels, diags = types.MapValueFrom(ctx, types.StringType, m)
				resp.Diagnostics.Append(diags...)
				if resp.Diagnostics.HasError() {
					return
				}
			}
		} else {
			plan.Labels = types.MapNull(types.StringType)
		}
	}

	// Hydrate top-level aliases (guarded: only when user configured aliases).
	// Filter out the server-auto-created key-name alias if not explicitly configured.
	// Sort result to match state alias order to avoid perpetual list diffs.
	if state.Aliases != nil {
		keyName := state.Name.ValueString()
		stateOrder := make(map[string]int, len(state.Aliases))
		configuredAliasNames := make(map[string]bool, len(state.Aliases))
		for i, sa := range state.Aliases {
			stateOrder[sa.Alias.ValueString()] = i
			configuredAliasNames[sa.Alias.ValueString()] = true
		}
		aliasesResult := gjson.Get(response, "aliases")
		if aliasesResult.Exists() && len(aliasesResult.Array()) > 0 {
			var aliases []*KeyAliasTFSDK
			for _, elem := range aliasesResult.Array() {
				aliasName := elem.Get("alias").String()
				if aliasName == keyName && !configuredAliasNames[keyName] {
					continue // skip server-auto-created key-name alias
				}
				a := &KeyAliasTFSDK{}
				if r := elem.Get("alias"); r.Exists() {
					a.Alias = types.StringValue(r.String())
				} else {
					a.Alias = types.StringNull()
				}
				if r := elem.Get("index"); r.Exists() {
					a.Index = types.StringValue(r.String())
				} else {
					a.Index = types.StringNull()
				}
				if r := elem.Get("type"); r.Exists() {
					a.Type = types.StringValue(r.String())
				} else {
					a.Type = types.StringNull()
				}
				aliases = append(aliases, a)
			}
			if aliases != nil {
				// Sort to match the state's alias order to avoid perpetual list diffs.
				sort.Slice(aliases, func(i, j int) bool {
					oi, okI := stateOrder[aliases[i].Alias.ValueString()]
					oj, okJ := stateOrder[aliases[j].Alias.ValueString()]
					if !okI {
						return false // new aliases go to the end
					}
					if !okJ {
						return true
					}
					return oi < oj
				})
				plan.Aliases = aliases
			} else {
				plan.Aliases = nil
			}
		} else {
			plan.Aliases = nil
		}
	}

	// Bug 4 fix — hydrate meta unconditionally
	metaResult := gjson.Get(response, "meta")
	if metaResult.Exists() && metaResult.Type != gjson.Null {
		var metaVal KeyMetadataTFSDK
		if r := gjson.Get(response, "meta.ownerId"); r.Exists() && r.String() != "" {
			metaVal.OwnerId = types.StringValue(r.String())
		} else {
			metaVal.OwnerId = types.StringNull()
		}
		permsResult := gjson.Get(response, "meta.permissions")
		if permsResult.Exists() && permsResult.Type != gjson.Null {
			var perms KeyMetadataPermissionsTFSDK
			for _, item := range gjson.Get(response, "meta.permissions.DecryptWithKey").Array() {
				perms.DecryptWithKey = append(perms.DecryptWithKey, types.StringValue(item.String()))
			}
			for _, item := range gjson.Get(response, "meta.permissions.EncryptWithKey").Array() {
				perms.EncryptWithKey = append(perms.EncryptWithKey, types.StringValue(item.String()))
			}
			for _, item := range gjson.Get(response, "meta.permissions.ExportKey").Array() {
				perms.ExportKey = append(perms.ExportKey, types.StringValue(item.String()))
			}
			for _, item := range gjson.Get(response, "meta.permissions.MACVerifyWithKey").Array() {
				perms.MACVerifyWithKey = append(perms.MACVerifyWithKey, types.StringValue(item.String()))
			}
			for _, item := range gjson.Get(response, "meta.permissions.MACWithKey").Array() {
				perms.MACWithKey = append(perms.MACWithKey, types.StringValue(item.String()))
			}
			for _, item := range gjson.Get(response, "meta.permissions.ReadKey").Array() {
				perms.ReadKey = append(perms.ReadKey, types.StringValue(item.String()))
			}
			for _, item := range gjson.Get(response, "meta.permissions.SignVerifyWithKey").Array() {
				perms.SignVerifyWithKey = append(perms.SignVerifyWithKey, types.StringValue(item.String()))
			}
			for _, item := range gjson.Get(response, "meta.permissions.SignWithKey").Array() {
				perms.SignWithKey = append(perms.SignWithKey, types.StringValue(item.String()))
			}
			for _, item := range gjson.Get(response, "meta.permissions.UseKey").Array() {
				perms.UseKey = append(perms.UseKey, types.StringValue(item.String()))
			}
			metaVal.Permissions = &perms
		} else {
			metaVal.Permissions = nil
		}
		cteResult := gjson.Get(response, "meta.cte")
		if cteResult.Exists() && cteResult.Type != gjson.Null {
			var cte KeyMetadataCTETFSDK
			if r := gjson.Get(response, "meta.cte.persistent_on_client"); r.Exists() {
				cte.PersistentOnClient = types.BoolValue(r.Bool())
			} else {
				cte.PersistentOnClient = types.BoolNull()
			}
			if r := gjson.Get(response, "meta.cte.encryption_mode"); r.Exists() {
				cte.EncryptionMode = types.StringValue(r.String())
			} else {
				cte.EncryptionMode = types.StringNull()
			}
			if r := gjson.Get(response, "meta.cte.cte_versioned"); r.Exists() {
				cte.CTEVersioned = types.BoolValue(r.Bool())
			} else {
				cte.CTEVersioned = types.BoolNull()
			}
			metaVal.CTE = &cte
		} else {
			metaVal.CTE = nil
		}
		plan.Metadata = &metaVal
	} else {
		plan.Metadata = nil
	}

	// public_key_parameters is a Create-only request field; GET /vault/keys2/{id} never
	// returns it (swagger-keys.yaml Key schema has no publicKeyParameters property).
	// Preserve whatever is in state to avoid perpetual drift for RSA keys that configure it.
	plan.PublicKeyParameters = state.PublicKeyParameters

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CMKeyTFSDK
	var state CMKeyTFSDK
	var payload CMKeyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ActivationDate.ValueString() != "" {
		payload.ActivationDate = plan.ActivationDate.ValueString()
	}
	// Build alias PATCH payload using the API's delta semantics:
	//   - add:    { alias, type }  (no index)  — alias not present in prior state
	//   - delete: { index }        (index only) — alias removed from plan
	//   Unchanged aliases (present in both state and plan) are NOT re-emitted;
	//   re-sending {alias, type, index} for an existing alias triggers a 409.
	var arrAlias []KeyAliasJSON

	stateAliasByName := make(map[string]*KeyAliasTFSDK, len(state.Aliases))
	for _, sa := range state.Aliases {
		stateAliasByName[sa.Alias.ValueString()] = sa
	}

	planAliasNames := make(map[string]bool, len(plan.Aliases))
	for _, alias := range plan.Aliases {
		planAliasNames[alias.Alias.ValueString()] = true
		if _, existsInState := stateAliasByName[alias.Alias.ValueString()]; !existsInState {
			// New alias not in state — ADD (no index).
			var aliasJSON KeyAliasJSON
			aliasJSON.Alias = alias.Alias.ValueString()
			if alias.Type.ValueString() != "" {
				aliasJSON.Type = alias.Type.ValueString()
			}
			arrAlias = append(arrAlias, aliasJSON)
		}
		// Unchanged aliases (in state and plan) are intentionally omitted.
	}

	// Emit delete entries for aliases in state but removed from plan.
	for _, sa := range state.Aliases {
		if !planAliasNames[sa.Alias.ValueString()] && sa.Index.ValueString() != "" {
			idx, _ := strconv.ParseInt(sa.Index.ValueString(), 10, 64)
			arrAlias = append(arrAlias, KeyAliasJSON{Index: &idx}) // delete: index only
		}
	}

	payload.Aliases = arrAlias

	if plan.ArchiveDate.ValueString() != "" {
		payload.ArchiveDate = plan.ArchiveDate.ValueString()
	}
	if plan.CompromiseOccurrenceDate.ValueString() != "" {
		payload.CompromiseOccurrenceDate = plan.CompromiseOccurrenceDate.ValueString()
	}
	if plan.DeactivationDate.ValueString() != "" {
		payload.DeactivationDate = plan.DeactivationDate.ValueString()
	}
	if plan.Description.ValueString() != "" {
		payload.Description = plan.Description.ValueString()
	}
	if plan.KeyId.ValueString() != "" {
		payload.KeyId = plan.KeyId.ValueString()
	}
	// Add meta to payload if set
	var metadata KeyMetadataJSON
	if plan.Metadata != nil {
		if plan.Metadata.OwnerId.ValueString() != "" {
			metadata.OwnerId = plan.Metadata.OwnerId.ValueString()
		}
		if plan.Metadata.Permissions != nil {
			var permission KeyMetadataPermissionsJSON
			var decryptWithKey []string
			var encryptWithKey []string
			var exportKey []string
			var macVerifyWithKey []string
			var macWithKey []string
			var readKey []string
			var signVerifyWithKey []string
			var signWithKey []string
			var useKey []string

			for _, str := range plan.Metadata.Permissions.DecryptWithKey {
				decryptWithKey = append(decryptWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.EncryptWithKey {
				encryptWithKey = append(encryptWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.ExportKey {
				exportKey = append(exportKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.MACVerifyWithKey {
				macVerifyWithKey = append(macVerifyWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.MACWithKey {
				macWithKey = append(macWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.ReadKey {
				readKey = append(readKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.SignVerifyWithKey {
				signVerifyWithKey = append(signVerifyWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.SignWithKey {
				signWithKey = append(signWithKey, str.ValueString())
			}
			for _, str := range plan.Metadata.Permissions.UseKey {
				useKey = append(useKey, str.ValueString())
			}
			permission.DecryptWithKey = decryptWithKey
			permission.EncryptWithKey = encryptWithKey
			permission.ExportKey = exportKey
			permission.MACVerifyWithKey = macVerifyWithKey
			permission.MACWithKey = macWithKey
			permission.ReadKey = readKey
			permission.SignVerifyWithKey = signVerifyWithKey
			permission.SignWithKey = signWithKey
			permission.UseKey = useKey
			metadata.Permissions = &permission
		}
		if plan.Metadata.CTE != nil {
			var cteParams KeyMetadataCTEJSON
			if !plan.Metadata.CTE.PersistentOnClient.IsNull() && !plan.Metadata.CTE.PersistentOnClient.IsUnknown() {
				cteParams.PersistentOnClient = plan.Metadata.CTE.PersistentOnClient.ValueBool()
			}
			if plan.Metadata.CTE.EncryptionMode.ValueString() != "" {
				cteParams.EncryptionMode = plan.Metadata.CTE.EncryptionMode.ValueString()
			}
			if !plan.Metadata.CTE.CTEVersioned.IsNull() && !plan.Metadata.CTE.CTEVersioned.IsUnknown() {
				cteParams.CTEVersioned = plan.Metadata.CTE.CTEVersioned.ValueBool()
			}
			metadata.CTE = &cteParams
		}
		payload.Metadata = &metadata
	}

	if plan.MUID.ValueString() != "" {
		payload.MUID = plan.MUID.ValueString()
	}
	if plan.ProcessStartDate.ValueString() != "" {
		payload.ProcessStartDate = plan.ProcessStartDate.ValueString()
	}
	if plan.ProtectStopDate.ValueString() != "" {
		payload.ProtectStopDate = plan.ProtectStopDate.ValueString()
	}
	if plan.RevocationMessage.ValueString() != "" {
		payload.RevocationMessage = plan.RevocationMessage.ValueString()
	}
	if plan.RevocationReason.ValueString() != "" {
		payload.RevocationReason = plan.RevocationReason.ValueString()
	}
	if plan.RotationFrequencyDays.ValueString() != "" {
		payload.RotationFrequencyDays = plan.RotationFrequencyDays.ValueString()
	}
	if !plan.UnDeletable.IsNull() && !plan.UnDeletable.IsUnknown() {
		v := plan.UnDeletable.ValueBool()
		payload.UnDeletable = &v
	}
	if !plan.UnExportable.IsNull() && !plan.UnExportable.IsUnknown() {
		v := plan.UnExportable.ValueBool()
		payload.UnExportable = &v
	}
	if !plan.UsageMask.IsNull() && !plan.UsageMask.IsUnknown() {
		payload.UsageMask = plan.UsageMask.ValueInt64()
	}
	if !plan.AllVersions.IsNull() && !plan.AllVersions.IsUnknown() {
		payload.AllVersions = plan.AllVersions.ValueBool()
	}
	// Add labels to payload
	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = labelsPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Key Update",
			err.Error(),
		)
		return
	}

	// UpdateDataV2 returns the full PATCH response body (KeyExtended), which lets us
	// pick up server-assigned alias indices for newly added aliases immediately.
	responseBody, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_KEY_MANAGEMENT, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating key on CipherTrust Manager: ",
			"Could not update key, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(responseBody, "id").String())

	// Resolve Optional bool fields that may remain unknown after PATCH if the user
	// did not explicitly configure them (IsUnknown means plan modifier left them open).
	if plan.XTS.IsUnknown() {
		plan.XTS = state.XTS
	}
	if plan.UnDeletable.IsUnknown() {
		plan.UnDeletable = state.UnDeletable
	}
	if plan.UnExportable.IsUnknown() {
		plan.UnExportable = state.UnExportable
	}

	// Hydrate bool fields from PATCH response so state reflects what the server accepted.
	if !plan.UnDeletable.IsNull() {
		if r := gjson.Get(responseBody, "undeletable"); r.Exists() {
			plan.UnDeletable = types.BoolValue(r.Bool())
		}
	}
	if !plan.UnExportable.IsNull() {
		if r := gjson.Get(responseBody, "unexportable"); r.Exists() {
			plan.UnExportable = types.BoolValue(r.Bool())
		}
	}

	// Re-hydrate aliases from PATCH response:
	//   - Unchanged aliases (were in state, not re-sent): preserve from state.
	//   - New aliases (were added): pick up server-assigned index from response.
	if plan.Aliases != nil {
		planOrder := make(map[string]int, len(plan.Aliases))
		for i, a := range plan.Aliases {
			planOrder[a.Alias.ValueString()] = i
		}

		serverAliasByName := make(map[string]gjson.Result)
		if aliasesResp := gjson.Get(responseBody, "aliases"); aliasesResp.Exists() {
			for _, elem := range aliasesResp.Array() {
				serverAliasByName[elem.Get("alias").String()] = elem
			}
		}

		var hydratedAliases []*KeyAliasTFSDK
		for _, planAlias := range plan.Aliases {
			aliasName := planAlias.Alias.ValueString()
			if sa, existsInState := stateAliasByName[aliasName]; existsInState {
				// Unchanged alias — preserve state entry (keeps existing index/type).
				hydratedAliases = append(hydratedAliases, sa)
			} else if elem, existsInServer := serverAliasByName[aliasName]; existsInServer {
				// Newly added alias — capture server-assigned index.
				na := &KeyAliasTFSDK{}
				na.Alias = types.StringValue(aliasName)
				if rv := elem.Get("index"); rv.Exists() {
					na.Index = types.StringValue(rv.String())
				} else {
					na.Index = types.StringNull()
				}
				if rv := elem.Get("type"); rv.Exists() {
					na.Type = types.StringValue(rv.String())
				} else {
					na.Type = types.StringNull()
				}
				hydratedAliases = append(hydratedAliases, na)
			}
		}
		if hydratedAliases != nil {
			sort.Slice(hydratedAliases, func(i, j int) bool {
				return planOrder[hydratedAliases[i].Alias.ValueString()] <
					planOrder[hydratedAliases[j].Alias.ValueString()]
			})
			plan.Aliases = hydratedAliases
		}
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_key.go -> Update]["+plan.ID.ValueString()+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMKeyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_KEY_MANAGEMENT, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_key.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "key is not deletable") && state.RemoveFromStateOnDestroy.ValueBool() {
			resp.Diagnostics.AddWarning("Ciphertrust key can't be deleted from CipherTrust Manager as it's undeletable but will be removed from state.",
				"key id: "+state.ID.ValueString(),
			)
		} else {
			resp.Diagnostics.AddError(
				"Error Deleting CipherTrust Key",
				"Could not delete key, unexpected error: "+err.Error(),
			)
		}
		return
	}
}

func (r *resourceCMKey) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (d *resourceCMKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
