package adp

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type ADPAccessPolicyUsersetPolicyTFSDK struct {
	ErrorReplacementValue types.String `tfsdk:"error_replacement_value"`
	MaskingFormatId       types.String `tfsdk:"masking_format_id"`
	RevealType            types.String `tfsdk:"reveal_type"`
	UserSetId             types.String `tfsdk:"user_set_id"`
}

type ADPAccessPolicyTFSDK struct {
	ID                           types.String                        `tfsdk:"id"`
	DefaultErrorReplacementValue types.String                        `tfsdk:"default_error_replacement_value"`
	DefaultMaskingFormatId       types.String                        `tfsdk:"default_masking_format_id"`
	DefaultRevealType            types.String                        `tfsdk:"default_reveal_type"`
	Description                  types.String                        `tfsdk:"description"`
	Name                         types.String                        `tfsdk:"name"`
	UsersetPolicy                []ADPAccessPolicyUsersetPolicyTFSDK `tfsdk:"user_set_policy"`
	ErrorReplacementValue        types.String                        `tfsdk:"error_replacement_value"`
	MaskingFormatId              types.String                        `tfsdk:"masking_format_id"`
	RevealType                   types.String                        `tfsdk:"reveal_type"`
	UpdateUsersetId              types.String                        `tfsdk:"update_user_set_id"`
	DeleteUsersetId              types.String                        `tfsdk:"delete_user_set_id"`
	URI                          types.String                        `tfsdk:"uri"`
	Account                      types.String                        `tfsdk:"account"`
	CreatedAt                    types.String                        `tfsdk:"created_at"`
	UpdatedAt                    types.String                        `tfsdk:"updated_at"`
}

type CreateAccessPolicyJSON struct {
	DefaultErrorReplacementValue string `json:"default_error_replacement_value"`
	DefaultMaskingFormatId       string `json:"default_masking_format_id"`
	DefaultRevealType            string `json:"default_reveal_type"`
	Description                  string `json:"description"`
	Name                         string `json:"name"`
}
type AddUsersetAccessPolicyJSON struct {
	ErrorReplacementValue string `json:"error_replacement_value"`
	MaskingFormatId       string `json:"masking_format_id"`
	RevealType            string `json:"reveal_type"`
	UserSetId             string `json:"user_set_id"`
}
type UpdateUsersetAccessPolicyJSON struct {
	ErrorReplacementValue string `json:"error_replacement_value"`
	MaskingFormatId       string `json:"masking_format_id"`
	RevealType            string `json:"reveal_type"`
}

type ADPProtectionPolicyTFSDK struct {
	ID                    types.String `tfsdk:"id"`
	AccessPolicyName      types.String `tfsdk:"access_policy_name"`
	Algorithm             types.String `tfsdk:"algorithm"`
	Key                   types.String `tfsdk:"key"`
	Name                  types.String `tfsdk:"name"`
	AAD                   types.String `tfsdk:"aad"`
	AllowSmallInput       types.Bool   `tfsdk:"allow_small_input"`
	CharacterSetId        types.String `tfsdk:"character_set_id"`
	DataFormat            types.String `tfsdk:"data_format"`
	Description           types.String `tfsdk:"description"`
	DisableVersioning     types.Bool   `tfsdk:"disable_versioning"`
	IV                    types.String `tfsdk:"iv"`
	MaskingFormatId       types.String `tfsdk:"masking_format_id"`
	Prefix                types.String `tfsdk:"prefix"`
	RandomNonce           types.String `tfsdk:"random_nonce"`
	TagLength             types.Int64  `tfsdk:"tag_length"`
	Tweak                 types.String `tfsdk:"tweak"`
	TweakAlgorithm        types.String `tfsdk:"tweak_algorithm"`
	UseExternalVersioning types.Bool   `tfsdk:"use_external_versioning"`
	URI                   types.String `tfsdk:"uri"`
	Account               types.String `tfsdk:"account"`
	CreatedAt             types.String `tfsdk:"created_at"`
	UpdatedAt             types.String `tfsdk:"updated_at"`
	Version               types.String `tfsdk:"version"`
	KeyName               types.String `tfsdk:"key_name"`
}

type ADPProtectionPolicyJSON struct {
	AccessPolicyName      string `json:"access_policy_name"`
	Algorithm             string `json:"algorithm"`
	Key                   string `json:"key"`
	Name                  string `json:"name"`
	AAD                   string `json:"aad"`
	AllowSmallInput       bool   `json:"allow_small_input"`
	CharacterSetId        string `json:"character_set_id"`
	DataFormat            string `json:"data_format"`
	Description           string `json:"description"`
	DisableVersioning     bool   `json:"disable_versioning"`
	IV                    string `json:"iv"`
	MaskingFormatId       string `json:"masking_format_id"`
	Prefix                string `json:"prefix"`
	RandomNonce           string `json:"random_nonce"`
	TagLength             int64  `json:"tag_length"`
	Tweak                 string `json:"tweak"`
	TweakAlgorithm        string `json:"tweak_algorithm"`
	UseExternalVersioning bool   `json:"use_external_versioning"`
}

type ADPClientProfileTFSDK struct {
	ID                      types.String   `tfsdk:"id"`
	AppConnectorType        types.String   `tfsdk:"app_connector_type"`
	Name                    types.String   `tfsdk:"name"`
	CAId                    types.String   `tfsdk:"ca_id"`
	CertDuration            types.Int64    `tfsdk:"cert_duration"`
	Configurations          types.Map      `tfsdk:"configurations"`
	CSRParameters           types.Map      `tfsdk:"csr_parameters"`
	EnableClientAutorenewal types.Bool     `tfsdk:"enable_client_autorenewal"`
	Groups                  []types.String `tfsdk:"groups"`
	HeartbeatThreshold      types.Int64    `tfsdk:"heartbeat_threshold"`
	JWTVerificationKey      types.String   `tfsdk:"jwt_verification_key"`
	Lifetime                types.String   `tfsdk:"lifetime"`
	MaxClients              types.Int64    `tfsdk:"max_clients"`
	NAEIfacePort            types.Int64    `tfsdk:"nae_iface_port"`
	PolicyId                types.String   `tfsdk:"policy_id"`
	URI                     types.String   `tfsdk:"uri"`
	Account                 types.String   `tfsdk:"account"`
	CreatedAt               types.String   `tfsdk:"created_at"`
	UpdatedAt               types.String   `tfsdk:"updated_at"`
	Owner                   types.String   `tfsdk:"owner"`
	RegToken                types.String   `tfsdk:"reg_token"`
}

type ADPClientProfileJSON struct {
	AppConnectorType        string                 `json:"app_connector_type"`
	Name                    string                 `json:"name"`
	CAId                    string                 `json:"ca_id"`
	CertDuration            int64                  `json:"cert_duration"`
	Configurations          map[string]interface{} `json:"configurations"`
	CSRParameters           map[string]interface{} `json:"csr_parameters"`
	EnableClientAutorenewal bool                   `json:"enable_client_autorenewal"`
	Groups                  []string               `json:"groups"`
	HeartbeatThreshold      int64                  `json:"heartbeat_threshold"`
	JWTVerificationKey      string                 `json:"jwt_verification_key"`
	Lifetime                string                 `json:"lifetime"`
	MaxClients              int64                  `json:"max_clients"`
	NAEIfacePort            int64                  `json:"nae_iface_port"`
	PolicyId                string                 `json:"policy_id"`
}

type DPGJsonRequestTokenTFSDK struct {
	Name                  types.String `tfsdk:"name"`
	Operation             types.String `tfsdk:"operation"`
	ProtectionPolicy      types.String `tfsdk:"protection_policy"`
	ExternalVersionHeader types.String `tfsdk:"external_version_header"`
}
type DPGJsonResponseTokenTFSDK struct {
	Name                  types.String `tfsdk:"name"`
	Operation             types.String `tfsdk:"operation"`
	ProtectionPolicy      types.String `tfsdk:"protection_policy"`
	AccessPolicy          types.String `tfsdk:"access_policy"`
	ExternalVersionHeader types.String `tfsdk:"external_version_header"`
}
type DPGJSONTokensTFSDK struct {
	APIUrl                   types.String                `tfsdk:"api_url"`
	DestinationUrl           types.String                `tfsdk:"destination_url"`
	JSONRequestPostTokens    []DPGJsonRequestTokenTFSDK  `tfsdk:"json_request_post_tokens"`
	JSONResponsePostTokens   []DPGJsonResponseTokenTFSDK `tfsdk:"json_response_post_tokens"`
	JSONRequestGetTokens     []DPGJsonRequestTokenTFSDK  `tfsdk:"json_request_get_tokens"`
	JSONResponseGetTokens    []DPGJsonResponseTokenTFSDK `tfsdk:"json_response_get_tokens"`
	JSONRequestPutTokens     []DPGJsonRequestTokenTFSDK  `tfsdk:"json_request_put_tokens"`
	JSONResponsePutTokens    []DPGJsonResponseTokenTFSDK `tfsdk:"json_response_put_tokens"`
	JSONRequestPatchTokens   []DPGJsonRequestTokenTFSDK  `tfsdk:"json_request_patch_tokens"`
	JSONResponsePatchTokens  []DPGJsonResponseTokenTFSDK `tfsdk:"json_response_patch_tokens"`
	JSONRequestDeleteTokens  []DPGJsonRequestTokenTFSDK  `tfsdk:"json_request_delete_tokens"`
	JSONResponseDeleteTokens []DPGJsonResponseTokenTFSDK `tfsdk:"json_response_delete_tokens"`
	URLRequestPostTokens     []DPGJsonRequestTokenTFSDK  `tfsdk:"url_request_post_tokens"`
	URLRequestGetTokens      []DPGJsonResponseTokenTFSDK `tfsdk:"url_request_get_tokens"`
	URLRequestPutTokens      []DPGJsonRequestTokenTFSDK  `tfsdk:"url_request_put_tokens"`
	URLRequestPatchTokens    []DPGJsonResponseTokenTFSDK `tfsdk:"url_request_patch_tokens"`
	URLRequestDeleteTokens   []DPGJsonRequestTokenTFSDK  `tfsdk:"url_request_delete_tokens"`
	ID                       types.String                `tfsdk:"id"`
	URI                      types.String                `tfsdk:"uri"`
	Account                  types.String                `tfsdk:"account"`
	CreatedAt                types.String                `tfsdk:"created_at"`
	UpdatedAt                types.String                `tfsdk:"updated_at"`
	DPGPolicyid              types.String                `tfsdk:"dpg_policy_id"`
}
type DPGPolicyTFSDK struct {
	ID                  types.String         `tfsdk:"id"`
	Name                types.String         `tfsdk:"name"`
	Description         types.String         `tfsdk:"description"`
	ProxyConfig         []DPGJSONTokensTFSDK `tfsdk:"proxy_config"`
	UpdateProxyConfigId types.String         `tfsdk:"update_api_url_id"`
	DeleteProxyConfigId types.String         `tfsdk:"delete_api_url_id"`
	URI                 types.String         `tfsdk:"uri"`
	Account             types.String         `tfsdk:"account"`
	CreatedAt           types.String         `tfsdk:"created_at"`
	UpdatedAt           types.String         `tfsdk:"updated_at"`
}

type DPGJsonRequestTokenJSON struct {
	Name                  string `json:"name"`
	Operation             string `json:"operation"`
	ProtectionPolicy      string `json:"protection_policy"`
	ExternalVersionHeader string `json:"external_version_header"`
}
type DPGJsonResponseTokenJSON struct {
	Name                  string `json:"name"`
	Operation             string `json:"operation"`
	ProtectionPolicy      string `json:"protection_policy"`
	AccessPolicy          string `json:"access_policy"`
	ExternalVersionHeader string `json:"external_version_header"`
}
type DPGJSONTokensJSON struct {
	APIUrl                   string                     `json:"api_url"`
	DestinationUrl           string                     `json:"destination_url"`
	JSONRequestPostTokens    []DPGJsonRequestTokenJSON  `json:"json_request_post_tokens"`
	JSONResponsePostTokens   []DPGJsonResponseTokenJSON `json:"json_response_post_tokens"`
	JSONRequestGetTokens     []DPGJsonRequestTokenJSON  `json:"json_request_get_tokens"`
	JSONResponseGetTokens    []DPGJsonResponseTokenJSON `json:"json_response_get_tokens"`
	JSONRequestPutTokens     []DPGJsonRequestTokenJSON  `json:"json_request_put_tokens"`
	JSONResponsePutTokens    []DPGJsonResponseTokenJSON `json:"json_response_put_tokens"`
	JSONRequestPatchTokens   []DPGJsonRequestTokenJSON  `json:"json_request_patch_tokens"`
	JSONResponsePatchTokens  []DPGJsonResponseTokenJSON `json:"json_response_patch_tokens"`
	JSONRequestDeleteTokens  []DPGJsonRequestTokenJSON  `json:"json_request_delete_tokens"`
	JSONResponseDeleteTokens []DPGJsonResponseTokenJSON `json:"json_response_delete_tokens"`
	URLRequestPostTokens     []DPGJsonRequestTokenJSON  `json:"url_request_post_tokens"`
	URLRequestGetTokens      []DPGJsonResponseTokenJSON `json:"url_request_get_tokens"`
	URLRequestPutTokens      []DPGJsonRequestTokenJSON  `json:"url_request_put_tokens"`
	URLRequestPatchTokens    []DPGJsonResponseTokenJSON `json:"url_request_patch_tokens"`
	URLRequestDeleteTokens   []DPGJsonRequestTokenJSON  `json:"url_request_delete_tokens"`
}
type DPGPolicyJSON struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	ProxyConfig []DPGJSONTokensJSON `json:"proxy_config"`
}
type DPGPolicyCreateJSON struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}
type DPGPolicyUpdateJSON struct {
	Description string `json:"description"`
}
