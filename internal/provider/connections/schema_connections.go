package connections

import "github.com/hashicorp/terraform-plugin-framework/types"

type IAMRoleAnywhereTFSDK struct {
	AnywhereRoleARN types.String `tfsdk:"anywhere_role_arn"`
	Certificate     types.String `tfsdk:"certificate"`
	ProfileARN      types.String `tfsdk:"profile_arn"`
	TrustAnchorARN  types.String `tfsdk:"trust_anchor_arn"`
	PrivateKey      types.String `tfsdk:"private_key"`
}

type AWSConnectionModelTFSDK struct {
	CMCreateConnectionResponseCommonTFSDK
	ID                      types.String          `tfsdk:"id"`
	Application             types.String          `tfsdk:"application"`
	DevAccount              types.String          `tfsdk:"dev_account"`
	Name                    types.String          `tfsdk:"name"`
	Description             types.String          `tfsdk:"description"`
	AccessKeyID             types.String          `tfsdk:"access_key_id"`
	AssumeRoleARN           types.String          `tfsdk:"assume_role_arn"`
	AssumeRoleExternalID    types.String          `tfsdk:"assume_role_external_id"`
	AWSRegion               types.String          `tfsdk:"aws_region"`
	AWSSTSRegionalEndpoints types.String          `tfsdk:"aws_sts_regional_endpoints"`
	CloudName               types.String          `tfsdk:"cloud_name"`
	IsRoleAnywhere          types.Bool            `tfsdk:"is_role_anywhere"`
	IAMRoleAnywhere         *IAMRoleAnywhereTFSDK `tfsdk:"iam_role_anywhere"`
	Labels                  types.Map             `tfsdk:"labels"`
	Meta                    types.Map             `tfsdk:"meta"`
	Products                []types.String        `tfsdk:"products"`
	SecretAccessKey         types.String          `tfsdk:"secret_access_key"`
}

type IAMRoleAnywhereJSON struct {
	AnywhereRoleARN string `json:"anywhere_role_arn"`
	Certificate     string `json:"certificate"`
	ProfileARN      string `json:"profile_arn"`
	TrustAnchorARN  string `json:"trust_anchor_arn"`
	PrivateKey      string `json:"private_key"`
}

type AWSConnectionModelJSON struct {
	CMCreateConnectionResponseCommon
	Application             types.String           `tfsdk:"application"`
	DevAccount              types.String           `tfsdk:"dev_account"`
	ID                      string                 `json:"id"`
	Name                    string                 `json:"name"`
	Description             string                 `json:"description"`
	AccessKeyID             string                 `json:"access_key_id"`
	AssumeRoleARN           string                 `json:"assume_role_arn"`
	AssumeRoleExternalID    string                 `json:"assume_role_external_id"`
	AWSRegion               string                 `json:"aws_region"`
	AWSSTSRegionalEndpoints string                 `json:"aws_sts_regional_endpoints"`
	CloudName               string                 `json:"cloud_name"`
	IsRoleAnywhere          bool                   `json:"is_role_anywhere"`
	IAMRoleAnywhere         *IAMRoleAnywhereJSON   `json:"iam_role_anywhere"`
	Labels                  map[string]interface{} `json:"labels"`
	Meta                    interface{}            `json:"meta"`
	Products                []string               `json:"products"`
	SecretAccessKey         string                 `json:"secret_access_key"`
}

type CMScpConnectionTFSDK struct {
	CMCreateConnectionResponseCommonTFSDK
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Products    types.List   `tfsdk:"products"`
	Meta        types.Map    `tfsdk:"meta"`
	Description types.String `tfsdk:"description"`
	Labels      types.Map    `tfsdk:"labels"`
	Host        types.String `tfsdk:"host"`
	Port        types.Int64  `tfsdk:"port"`
	Username    types.String `tfsdk:"username"`
	AuthMethod  types.String `tfsdk:"auth_method"`
	PathTo      types.String `tfsdk:"path_to"`
	Protocol    types.String `tfsdk:"protocol"`
	Password    types.String `tfsdk:"password"`
	PublicKey   types.String `tfsdk:"public_key"`
}

type CMScpConnectionJSON struct {
	CMCreateConnectionResponseCommon
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Products    []string               `json:"products"`
	Meta        interface{}            `json:"meta"`
	Description string                 `json:"description"`
	Labels      map[string]interface{} `json:"labels"`
	Host        string                 `json:"host"`
	Port        int64                  `json:"port"`
	Username    string                 `json:"username"`
	AuthMethod  string                 `json:"auth_method"`
	PathTo      string                 `json:"path_to"`
	Protocol    string                 `json:"protocol"`
	Password    string                 `json:"password"`
	PublicKey   string                 `json:"public_key"`
}

type CMCreateConnectionResponseCommonTFSDK struct {
	URI                 types.String `tfsdk:"uri"`
	Account             types.String `tfsdk:"account"`
	CreatedAt           types.String `tfsdk:"created_at"`
	UpdatedAt           types.String `tfsdk:"updated_at"`
	Service             types.String `tfsdk:"service"`
	Category            types.String `tfsdk:"category"`
	ResourceURL         types.String `tfsdk:"resource_url"`
	LastConnectionOK    types.Bool   `tfsdk:"last_connection_ok"`
	LastConnectionError types.String `tfsdk:"last_connection_error"`
	LastConnectionAt    types.String `tfsdk:"last_connection_at"`
}

type CMCreateConnectionResponseCommon struct {
	URI                 string `json:"uri"`
	Account             string `json:"account"`
	CreatedAt           string `json:"createdAt"`
	UpdatedAt           string `json:"updatedAt"`
	Service             string `json:"service"`
	Category            string `json:"category"`
	ResourceURL         string `json:"resource_url"`
	LastConnectionOK    bool   `json:"last_connection_ok"`
	LastConnectionError string `json:"last_connection_error"`
	LastConnectionAt    string `json:"last_connection_at"`
}

type AzureConnectionTFSDK struct {
	CMCreateConnectionResponseCommonTFSDK
	ID                       types.String `tfsdk:"id"`
	ClientID                 types.String `tfsdk:"client_id"`
	Name                     types.String `tfsdk:"name"`
	TenantID                 types.String `tfsdk:"tenant_id"`
	ActiveDirectoryEndpoint  types.String `tfsdk:"active_directory_endpoint"`
	AzureStackConnectionType types.String `tfsdk:"azure_stack_connection_type"`
	AzureStackServerCert     types.String `tfsdk:"azure_stack_server_cert"`
	CertDuration             types.Int64  `tfsdk:"cert_duration"`
	Certificate              types.String `tfsdk:"certificate"`
	ClientSecret             types.String `tfsdk:"client_secret"`
	CloudName                types.String `tfsdk:"cloud_name"`
	Description              types.String `tfsdk:"description"`
	ExternalCertificateUsed  types.Bool   `tfsdk:"external_certificate_used"`
	IsCertificateUsed        types.Bool   `tfsdk:"is_certificate_used"`
	KeyVaultDNSSuffix        types.String `tfsdk:"key_vault_dns_suffix"`
	Labels                   types.Map    `tfsdk:"labels"`
	ManagementURL            types.String `tfsdk:"management_url"`
	Meta                     types.Map    `tfsdk:"meta"`
	Products                 types.List   `tfsdk:"products"`
	ResourceManagerURL       types.String `tfsdk:"resource_manager_url"`
	VaultResourceURL         types.String `tfsdk:"vault_resource_url"`
	CertificateThumbprint    types.String `tfsdk:"certificate_thumbprint"`
}

type AzureConnectionJSON struct {
	CMCreateConnectionResponseCommon
	ID                       string                 `json:"id"`
	ClientID                 string                 `json:"client_id"`
	Name                     string                 `json:"name"`
	TenantID                 string                 `json:"tenant_id"`
	ActiveDirectoryEndpoint  string                 `json:"active_directory_endpoint"`
	AzureStackConnectionType string                 `json:"azure_stack_connection_type"`
	AzureStackServerCert     string                 `json:"azure_stack_server_cert"`
	CertDuration             int64                  `json:"cert_duration"`
	Certificate              string                 `json:"certificate"`
	ClientSecret             string                 `json:"client_secret"`
	CloudName                string                 `json:"cloud_name"`
	Description              string                 `json:"description"`
	ExternalCertificateUsed  bool                   `json:"external_certificate_used"`
	IsCertificateUsed        bool                   `json:"is_certificate_used"`
	KeyVaultDNSSuffix        string                 `json:"key_vault_dns_suffix"`
	Labels                   map[string]interface{} `json:"labels"`
	ManagementURL            string                 `json:"management_url"`
	Meta                     interface{}            `json:"meta"`
	Products                 []string               `json:"products"`
	ResourceManagerURL       string                 `json:"resource_manager_url"`
	VaultResourceURL         string                 `json:"vault_resource_url"`
	CertificateThumbprint    string                 `json:"certificate_thumbprint"`
}

type GCPConnectionTFSDK struct {
	CMCreateConnectionResponseCommonTFSDK
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Products     types.List   `tfsdk:"products"`
	Meta         types.Map    `tfsdk:"meta"`
	Description  types.String `tfsdk:"description"`
	Labels       types.Map    `tfsdk:"labels"`
	CloudName    types.String `tfsdk:"cloud_name"`
	KeyFile      types.String `tfsdk:"key_file"`
	ClientEmail  types.String `tfsdk:"client_email"`
	PrivateKeyID types.String `tfsdk:"private_key_id"`
}

type GCPConnectionJSON struct {
	CMCreateConnectionResponseCommon
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Products     []string               `json:"products"`
	Meta         interface{}            `json:"meta"`
	Description  string                 `json:"description"`
	Labels       map[string]interface{} `json:"labels"`
	CloudName    string                 `json:"cloud_name"`
	KeyFile      string                 `json:"key_file"`
	ClientEmail  string                 `json:"client_email"`
	PrivateKeyID string                 `json:"private_key_id"`
}
