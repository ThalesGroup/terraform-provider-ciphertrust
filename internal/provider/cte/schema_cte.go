package cte

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type CTEClientsListTFSDK struct {
	ID                     types.String   `tfsdk:"id"`
	URI                    types.String   `tfsdk:"uri"`
	Account                types.String   `tfsdk:"account"`
	App                    types.String   `tfsdk:"application"`
	DevAccount             types.String   `tfsdk:"dev_account"`
	CreatedAt              types.String   `tfsdk:"created_at"`
	UpdatedAt              types.String   `tfsdk:"updated_at"`
	Name                   types.String   `tfsdk:"name"`
	OSType                 types.String   `tfsdk:"os_type"`
	OSSubType              types.String   `tfsdk:"os_sub_type"`
	ClientRegID            types.String   `tfsdk:"client_reg_id"`
	ServerHostname         types.String   `tfsdk:"server_host_name"`
	Description            types.String   `tfsdk:"description"`
	ClientLocked           types.Bool     `tfsdk:"client_locked"`
	SystemLocked           types.Bool     `tfsdk:"system_locked"`
	PasswordCreationMethod types.String   `tfsdk:"password_creation_method"`
	ClientVersion          types.Int64    `tfsdk:"client_version"`
	RegistrationAllowed    types.Bool     `tfsdk:"registration_allowed"`
	CommunicationEnabled   types.Bool     `tfsdk:"communication_enabled"`
	Capabilities           types.String   `tfsdk:"capabilities"`
	EnabledCapabilities    types.String   `tfsdk:"enabled_capabilities"`
	ProtectionMode         types.String   `tfsdk:"protection_mode"`
	ClientType             types.String   `tfsdk:"client_type"`
	ProfileName            types.String   `tfsdk:"profile_name"`
	ProfileID              types.String   `tfsdk:"profile_id"`
	LDTEnabled             types.Bool     `tfsdk:"ldt_enabled"`
	ClientHealthStatus     types.String   `tfsdk:"client_health_status"`
	Errors                 []types.String `tfsdk:"errors"`
	Warnings               []types.String `tfsdk:"warnings"`
	ClientErrors           []types.String `tfsdk:"client_errors"`
	ClientWarnings         []types.String `tfsdk:"client_warnings"`
}

type CTEClientsListJSON struct {
	ID                     string   `json:"id"`
	URI                    string   `json:"uri"`
	Account                string   `json:"account"`
	App                    string   `json:"application"`
	DevAccount             string   `json:"dev_account"`
	CreatedAt              string   `json:"created_at"`
	UpdatedAt              string   `json:"updated_at"`
	Name                   string   `json:"name"`
	OSType                 string   `json:"os_type"`
	OSSubType              string   `json:"os_sub_type"`
	ClientRegID            string   `json:"client_reg_id"`
	ServerHostname         string   `json:"server_host_name"`
	Description            string   `json:"description"`
	ClientLocked           bool     `json:"client_locked"`
	SystemLocked           bool     `json:"system_locked"`
	PasswordCreationMethod string   `json:"password_creation_method"`
	ClientVersion          int64    `json:"client_version"`
	RegistrationAllowed    bool     `json:"registration_allowed"`
	CommunicationEnabled   bool     `json:"communication_enabled"`
	Capabilities           string   `json:"capabilities"`
	EnabledCapabilities    string   `json:"enabled_capabilities"`
	ProtectionMode         string   `json:"protection_mode"`
	ClientType             string   `json:"client_type"`
	ProfileName            string   `json:"profile_name"`
	ProfileID              string   `json:"profile_id"`
	LDTEnabled             bool     `json:"ldt_enabled"`
	ClientHealthStatus     string   `json:"client_health_status"`
	Errors                 []string `json:"errors"`
	Warnings               []string `json:"warnings"`
	ClientErrors           []string `json:"client_errors"`
	ClientWarnings         []string `json:"client_warnings"`
}

type CTEClientTFSDK struct {
	ID                     types.String   `tfsdk:"id"`
	Name                   types.String   `tfsdk:"name"`
	ClientLocked           types.Bool     `tfsdk:"client_locked"`
	ClientType             types.String   `tfsdk:"client_type"`
	CommunicationEnabled   types.Bool     `tfsdk:"communication_enabled"`
	Description            types.String   `tfsdk:"description"`
	Password               types.String   `tfsdk:"password"`
	PasswordCreationMethod types.String   `tfsdk:"password_creation_method"`
	ProfileIdentifier      types.String   `tfsdk:"profile_identifier"`
	RegistrationAllowed    types.Bool     `tfsdk:"registration_allowed"`
	SystemLocked           types.Bool     `tfsdk:"system_locked"`
	ClientMFAEnabled       types.Bool     `tfsdk:"client_mfa_enabled"`
	DelClient              types.Bool     `tfsdk:"del_client"`
	DisableCapability      types.String   `tfsdk:"disable_capability"`
	DynamicParameters      types.String   `tfsdk:"dynamic_parameters"`
	EnableDomainSharing    types.Bool     `tfsdk:"enable_domain_sharing"`
	EnabledCapabilities    types.String   `tfsdk:"enabled_capabilities"`
	LGCSAccessOnly         types.Bool     `tfsdk:"lgcs_access_only"`
	MaxNumCacheLog         types.Int64    `tfsdk:"max_num_cache_log"`
	MaxSpaceCacheLog       types.Int64    `tfsdk:"max_space_cache_log"`
	ProfileID              types.String   `tfsdk:"profile_id"`
	ProtectionMode         types.String   `tfsdk:"protection_mode"`
	SharedDomainList       []types.String `tfsdk:"shared_domain_list"`
	Labels                 types.Map      `tfsdk:"labels"`
}

type CTEClientJSON struct {
	ID                     string                 `json:"id"`
	Name                   string                 `json:"name"`
	ClientLocked           bool                   `json:"client_locked,omitempty"`
	ClientType             string                 `json:"client_type"`
	CommunicationEnabled   bool                   `json:"communication_enabled"`
	Description            string                 `json:"description"`
	Password               string                 `json:"password,omitempty"`
	PasswordCreationMethod string                 `json:"password_creation_method"`
	ProfileIdentifier      string                 `json:"profile_identifier"`
	RegistrationAllowed    bool                   `json:"registration_allowed"`
	SystemLocked           bool                   `json:"system_locked,omitempty"`
	ClientMFAEnabled       bool                   `json:"client_mfa_enabled,omitempty"`
	DelClient              bool                   `json:"del_client"`
	DisableCapability      string                 `json:"disable_capability"`
	DynamicParameters      string                 `json:"dynamic_parameters,omitempty"`
	EnableDomainSharing    bool                   `json:"enable_domain_sharing"`
	EnabledCapabilities    string                 `json:"enabled_capabilities,omitempty"`
	LGCSAccessOnly         bool                   `json:"lgcs_access_only,omitempty"`
	MaxNumCacheLog         int64                  `json:"max_num_cache_log"`
	MaxSpaceCacheLog       int64                  `json:"max_space_cache_log"`
	ProfileID              string                 `json:"profile_id"`
	ProtectionMode         string                 `json:"protection_mode,omitempty"`
	SharedDomainList       []string               `json:"shared_domain_list"`
	Labels                 map[string]interface{} `json:"labels"`
}

// CTE client delete payload struct
type DelClientJSON struct {
	DelClient      bool `json:"del_client"`
	ForceDelClient bool `json:"force_del_client"`
}

// CTE Policy related structs
type DataTxRuleJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type"`
	ResourceSetID string `json:"resource_set_id"`
}

type IDTRuleJSON struct {
	CurrentKey            string `json:"current_key"`
	CurrentKeyType        string `json:"current_key_type"`
	TransformationKey     string `json:"transformation_key"`
	TransformationKeyType string `json:"transformation_key_type"`
}

type KeyRuleJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type"`
	ResourceSetID string `json:"resource_set_id"`
}

type CurrentKeyJSON struct {
	KeyID   string `json:"key_id,omitempty"`
	KeyType string `json:"key_type,omitempty"`
}

type TransformationKeyJSON struct {
	KeyID   string `json:"key_id,omitempty"`
	KeyType string `json:"key_type,omitempty"`
}

type LDTRuleJSON struct {
	CurrentKey        CurrentKeyJSON        `json:"current_key"`
	TransformationKey TransformationKeyJSON `json:"transformation_key"`
	IsExclusionRule   bool                  `json:"is_exclusion_rule"`
	ResourceSetID     string                `json:"resource_set_id"`
}

type CTEPolicyMetadataJSON struct {
	RestrictUpdate bool `json:"restrict_update"`
}

type SecurityRuleJSON struct {
	Action             string `json:"action"`
	Effect             string `json:"effect"`
	ExcludeProcessSet  bool   `json:"exclude_process_set"`
	ExcludeResourceSet bool   `json:"exclude_resource_set"`
	ExcludeUserSet     bool   `json:"exclude_user_set"`
	PartialMatch       bool   `json:"partial_match"`
	ProcessSetID       string `json:"process_set_id"`
	ResourceSetID      string `json:"resource_set_id"`
	UserSetID          string `json:"user_set_id"`
}

type SignatureRuleJSON struct {
	SignatureSetID string `json:"signature_set_id"`
}

type AddSignaturesToRuleJSON struct {
	SignatureSets []string `json:"signature_set_id_list"`
}

type CTEPolicyJSON struct {
	ID                  string                `json:"id"`
	Name                string                `json:"name"`
	Description         string                `json:"description"`
	PolicyType          string                `json:"policy_type"`
	Metadata            CTEPolicyMetadataJSON `json:"metadata"`
	NeverDeny           bool                  `json:"never_deny"`
	DataTransformRules  []DataTxRuleJSON      `json:"data_transform_rules"`
	IDTKeyRules         []IDTRuleJSON         `json:"idt_key_rules"`
	KeyRules            []KeyRuleJSON         `json:"key_rules"`
	LDTKeyRules         []LDTRuleJSON         `json:"ldt_key_rules"`
	SecurityRules       []SecurityRuleJSON    `json:"security_rules"`
	SignatureRules      []SignatureRuleJSON   `json:"signature_rules"`
	ForceRestrictUpdate bool                  `json:"force_restrict_update"`
}

type DataTransformationRuleTFSDK struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type IDTKeyRuleTFSDK struct {
	CurrentKey            types.String `tfsdk:"current_key"`
	CurrentKeyType        types.String `tfsdk:"current_key_type"`
	TransformationKey     types.String `tfsdk:"transformation_key"`
	TransformationKeyType types.String `tfsdk:"transformation_key_type"`
}

type KeyRuleTFSDK struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type CurrentKeyTFSDK struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type TransformationKeyTFSDK struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type LDTKeyRuleTFSDK struct {
	CurrentKey        CurrentKeyTFSDK        `tfsdk:"current_key"`
	TransformationKey TransformationKeyTFSDK `tfsdk:"transformation_key"`
	IsExclusionRule   types.Bool             `tfsdk:"is_exclusion_rule"`
	ResourceSetID     types.String           `tfsdk:"resource_set_id"`
}

type CTEPolicyMetadataTFSDK struct {
	RestrictUpdate types.Bool `tfsdk:"restrict_update"`
}

type SecurityRuleTFSDK struct {
	Action             types.String `tfsdk:"action"`
	Effect             types.String `tfsdk:"effect"`
	ExcludeProcessSet  types.Bool   `tfsdk:"exclude_process_set"`
	ExcludeResourceSet types.Bool   `tfsdk:"exclude_resource_set"`
	ExcludeUserSet     types.Bool   `tfsdk:"exclude_user_set"`
	PartialMatch       types.Bool   `tfsdk:"partial_match"`
	ProcessSetID       types.String `tfsdk:"process_set_id"`
	ResourceSetID      types.String `tfsdk:"resource_set_id"`
	UserSetID          types.String `tfsdk:"user_set_id"`
}

type SignatureRuleTFSDK struct {
	SignatureSetID types.String `tfsdk:"signature_set_id"`
}

type CTEPolicyTFSDK struct {
	ID                  types.String                  `tfsdk:"id"`
	Name                types.String                  `tfsdk:"name"`
	Description         types.String                  `tfsdk:"description"`
	PolicyType          types.String                  `tfsdk:"policy_type"`
	Metadata            *CTEPolicyMetadataTFSDK       `tfsdk:"metadata"`
	NeverDeny           types.Bool                    `tfsdk:"never_deny"`
	DataTransformRules  []DataTransformationRuleTFSDK `tfsdk:"data_transform_rules"`
	IDTKeyRules         []IDTKeyRuleTFSDK             `tfsdk:"idt_key_rules"`
	KeyRules            []KeyRuleTFSDK                `tfsdk:"key_rules"`
	LDTKeyRules         []LDTKeyRuleTFSDK             `tfsdk:"ldt_key_rules"`
	SecurityRules       []SecurityRuleTFSDK           `tfsdk:"security_rules"`
	SignatureRules      []SignatureRuleTFSDK          `tfsdk:"signature_rules"`
	ForceRestrictUpdate types.Bool                    `tfsdk:"force_restrict_update"`
}

type CTEPolicyDataTxRulesListTFSDK struct {
	ID            types.String `tfsdk:"id"`
	URI           types.String `tfsdk:"uri"`
	Account       types.String `tfsdk:"account"`
	Application   types.String `tfsdk:"application"`
	DevAccount    types.String `tfsdk:"dev_account"`
	CreateAt      types.String `tfsdk:"created_at"`
	UpdatedAt     types.String `tfsdk:"updated_at"`
	PolicyID      types.String `tfsdk:"policy_id"`
	OrderNumber   types.Int64  `tfsdk:"order_number"`
	KeyID         types.String `tfsdk:"key_id"`
	NewKeyRule    types.Bool   `tfsdk:"new_key_rule"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type CTEPolicyIDTKeyRulesListTFSDK struct {
	ID                types.String `tfsdk:"id"`
	PolicyID          types.String `tfsdk:"policy_id"`
	CurrentKey        types.String `tfsdk:"current_key"`
	TransformationKey types.String `tfsdk:"transformation_key"`
}

type CTEPolicyLDTKeyRulesListTFSDK struct {
	ID                    types.String `tfsdk:"id"`
	PolicyID              types.String `tfsdk:"policy_id"`
	OrderNumber           types.Int64  `tfsdk:"order_number"`
	ResourceSetID         types.String `tfsdk:"resource_set_id"`
	CurrentKeyID          types.String `tfsdk:"current_key_id"`
	CurrentKeyType        types.String `tfsdk:"current_key_type"`
	TransformationKeyID   types.String `tfsdk:"transformation_key_id"`
	TransformationKeyType types.String `tfsdk:"transformation_key_type"`
	ISExclusionRule       types.Bool   `tfsdk:"is_exclusion_rule"`
}

type tfsdkCTEPolicyIDTKeyRulesListModel struct {
	ID                types.String `tfsdk:"id"`
	PolicyID          types.String `tfsdk:"policy_id"`
	CurrentKey        types.String `tfsdk:"current_key"`
	TransformationKey types.String `tfsdk:"transformation_key"`
}

type CTEPolicySecurityRulesListTFSDK struct {
	ID                 types.String `tfsdk:"id"`
	URI                types.String `tfsdk:"uri"`
	Account            types.String `tfsdk:"account"`
	Application        types.String `tfsdk:"application"`
	DevAccount         types.String `tfsdk:"dev_account"`
	CreatedAt          types.String `tfsdk:"created_at"`
	UpdatedAt          types.String `tfsdk:"updated_at"`
	PolicyID           types.String `tfsdk:"policy_id"`
	OrderNumber        types.Int64  `tfsdk:"order_number"`
	Action             types.String `tfsdk:"action"`
	Effect             types.String `tfsdk:"effect"`
	UserSetID          types.String `tfsdk:"user_set_id"`
	ExcludeUserSet     types.Bool   `tfsdk:"exclude_user_set"`
	ResourceSetID      types.String `tfsdk:"resource_set_id"`
	ExcludeResourceSet types.Bool   `tfsdk:"exclude_resource_set"`
	ProcessSetID       types.String `tfsdk:"process_set_id"`
	ExcludeProcessSet  types.Bool   `tfsdk:"exclude_process_set"`
	PartialMatch       types.Bool   `tfsdk:"partial_match"`
}

type CTEPolicySignatureRulesListTFSDK struct {
	ID               types.String `tfsdk:"id"`
	URI              types.String `tfsdk:"uri"`
	Account          types.String `tfsdk:"account"`
	CreatedAt        types.String `tfsdk:"created_at"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
	PolicyID         types.String `tfsdk:"policy_id"`
	SignatureSetID   types.String `tfsdk:"signature_set_id"`
	SignatureSetName types.String `tfsdk:"signature_set_name"`
}

type CTEPolicyDataTxRulesJSON struct {
	ID            string `json:"id"`
	URI           string `json:"uri"`
	Account       string `json:"account"`
	Application   string `json:"application"`
	DevAccount    string `json:"dev_account"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
	PolicyID      string `json:"policy_id"`
	OrderNumber   int64  `json:"order_number"`
	KeyID         string `json:"key_id"`
	NewKeyRule    bool   `json:"new_key_rule"`
	ResourceSetID string `json:"resource_set_id"`
}

type CTEPolicyIDTKeyRulesJSON struct {
	ID                string `json:"id"`
	PolicyID          string `json:"policy_id"`
	CurrentKey        string `json:"current_key"`
	TransformationKey string `json:"transformation_key"`
}

type CTEPolicyLDTKeyRulesJSON struct {
	ID                string                `json:"id"`
	PolicyID          string                `json:"policy_id"`
	OrderNumber       int64                 `json:"order_number"`
	ResourceSetID     string                `json:"resource_set_id"`
	CurrentKey        CurrentKeyJSON        `json:"current_key"`
	TransformationKey TransformationKeyJSON `json:"transformation_key"`
	ISExclusionRule   bool                  `json:"is_exclusion_rule"`
}

type CTEPolicySecurityRulesJSON struct {
	ID                 string `json:"id"`
	URI                string `json:"uri"`
	Account            string `json:"account"`
	Application        string `json:"application"`
	DevAccount         string `json:"dev_account"`
	CreatedAt          string `json:"createdAt"`
	UpdatedAt          string `json:"updatedAt"`
	PolicyID           string `json:"policy_id"`
	OrderNumber        int64  `json:"order_number"`
	Action             string `json:"action"`
	Effect             string `json:"effect"`
	UserSetID          string `json:"user_set_id"`
	ExcludeUserSet     bool   `json:"exclude_user_set"`
	ResourceSetID      string `json:"resource_set_id"`
	ExcludeResourceSet bool   `json:"exclude_resource_set"`
	ProcessSetID       string `json:"process_set_id"`
	ExcludeProcessSet  bool   `json:"exclude_process_set"`
	PartialMatch       bool   `json:"partial_match"`
}

type CTEPolicySignatureRulesJSON struct {
	ID               string `json:"id"`
	URI              string `json:"uri"`
	Account          string `json:"account"`
	CreatedAt        string `json:"createdAt"`
	UpdatedAt        string `json:"updatedAt"`
	PolicyID         string `json:"policy_id"`
	SignatureSetID   string `json:"signature_set_id"`
	SignatureSetName string `json:"signature_set_name"`
}

type AddDataTXRulePolicyTFSDK struct {
	CTEClientPolicyID types.String                `tfsdk:"policy_id"`
	DataTXRuleID      types.String                `tfsdk:"rule_id"`
	OrderNumber       types.Int64                 `tfsdk:"order_number"`
	DataTXRule        DataTransformationRuleTFSDK `tfsdk:"rule"`
}

type DataTxRuleUpdateJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type,omitempty"`
	ResourceSetID string `json:"resource_set_id,omitempty"`
	OrderNumber   int64  `json:"order_number,omitempty"`
}

type KeyRuleUpdateJSON struct {
	KeyID         string `json:"key_id"`
	KeyType       string `json:"key_type,omitempty"`
	ResourceSetID string `json:"resource_set_id,omitempty"`
	OrderNumber   int64  `json:"order_number,omitempty"`
}

type LDTRuleUpdateJSON struct {
	CurrentKey        CurrentKeyJSON        `json:"current_key"`
	TransformationKey TransformationKeyJSON `json:"transformation_key"`
	IsExclusionRule   bool                  `json:"is_exclusion_rule,omitempty"`
	ResourceSetID     string                `json:"resource_set_id,omitempty"`
	OrderNumber       int64                 `json:"order_number,omitempty"`
}

type SecurityRuleUpdateJSON struct {
	Action             string `json:"action,omitempty"`
	Effect             string `json:"effect,omitempty"`
	ExcludeProcessSet  bool   `json:"exclude_process_set,omitempty"`
	ExcludeResourceSet bool   `json:"exclude_resource_set,omitempty"`
	ExcludeUserSet     bool   `json:"exclude_user_set,omitempty"`
	PartialMatch       bool   `json:"partial_match,omitempty"`
	ProcessSetID       string `json:"process_set_id,omitempty"`
	ResourceSetID      string `json:"resource_set_id,omitempty"`
	UserSetID          string `json:"user_set_id,omitempty"`
	OrderNumber        int64  `json:"order_number,omitempty"`
}

type UpdateIDTKeyRulePolicyTFSDK struct {
	CTEClientPolicyID types.String    `tfsdk:"policy_id"`
	IDTKeyRuleID      types.String    `tfsdk:"rule_id"`
	IDTKeyRule        IDTKeyRuleTFSDK `tfsdk:"rule"`
}

type CTEProcessSetListItemTFSDK struct {
	Index         types.Int64  `tfsdk:"index"`
	Directory     types.String `tfsdk:"directory"`
	File          types.String `tfsdk:"file"`
	Signature     types.String `tfsdk:"signature"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type CTEProcessSetsListTFSDK struct {
	ID          types.String                 `tfsdk:"id"`
	Name        types.String                 `tfsdk:"name"`
	Description types.String                 `tfsdk:"description"`
	URI         types.String                 `tfsdk:"uri"`
	Account     types.String                 `tfsdk:"account"`
	CreateAt    types.String                 `tfsdk:"created_at"`
	UpdatedAt   types.String                 `tfsdk:"updated_at"`
	Processes   []CTEProcessSetListItemTFSDK `tfsdk:"resources"`
}

type CTEProcessSetListItemJSON struct {
	ID          string                   `json:"id"`
	URI         string                   `json:"uri"`
	Account     string                   `json:"account"`
	CreatedAt   string                   `json:"createdAt"`
	Name        string                   `json:"name"`
	UpdatedAt   string                   `json:"updatedAt"`
	Description string                   `json:"description"`
	Processes   []CTEProcessSetsListJSON `json:"resources"`
}

type CTEProcessSetsListJSON struct {
	Index         int64  `json:"index"`
	Directory     string `json:"directory"`
	File          string `json:"file"`
	Signature     string `json:"signature"`
	ResourceSetID string `json:"resource_set_id"`
}

type CTEProfilesListTFSDK struct {
	ID                     types.String `tfsdk:"id"`
	URI                    types.String `tfsdk:"uri"`
	Account                types.String `tfsdk:"account"`
	Application            types.String `tfsdk:"application"`
	CreatedAt              types.String `tfsdk:"created_at"`
	UpdatedAt              types.String `tfsdk:"updated_at"`
	Name                   types.String `tfsdk:"name"`
	Description            types.String `tfsdk:"description"`
	LDTQOSCapCPUAllocation types.Bool   `tfsdk:"ldt_qos_cap_cpu_allocation"`
	LDTQOSCapCPUPercent    types.Int64  `tfsdk:"ldt_qos_cpu_percent"`
	LDTQOSRekeyOption      types.String `tfsdk:"ldt_qos_rekey_option"`
	LDTQOSRekeyRate        types.Int64  `tfsdk:"ldt_qos_rekey_rate"`
	ConciseLogging         types.Bool   `tfsdk:"concise_logging"`
	ConnectTimeout         types.Int64  `tfsdk:"connect_timeout"`
	LDTQOSSchedule         types.String `tfsdk:"ldt_qos_schedule"`
	LDTQOSStatusCheckRate  types.Int64  `tfsdk:"ldt_qos_status_check_rate"`
	MetadataScanInterval   types.Int64  `tfsdk:"metadata_scan_interval"`
	MFAExemptUserSetID     types.String `tfsdk:"mfa_exempt_user_set_id"`
	MFAExemptUserSetName   types.String `tfsdk:"mfa_exempt_user_set_name"`
	OIDCConnectionID       types.String `tfsdk:"oidc_connection_id"`
	OIDCConnectionName     types.String `tfsdk:"oidc_connection_name"`
	RWPOperation           types.String `tfsdk:"rwp_operation"`
	RWPProcessSet          types.String `tfsdk:"rwp_process_set"`
	ServerResponseRate     types.Int64  `tfsdk:"server_response_rate"`
	//QOSSchedules            []tfsdkCTEProfileQOSSchedule           `tfsdk:"qos_schedules"`
	//ServerSettings          []tfsdkCTEProfileServiceSetting        `tfsdk:"server_settings"`
	// ManagementServiceLogger tfsdkCTEProfileManagementServiceLogger `tfsdk:"management_service_logger"`
	// PolicyEvaluationLogger  tfsdkCTEProfileManagementServiceLogger `tfsdk:"policy_evaluation_logger"`
	// SecurityAdminLogger     tfsdkCTEProfileManagementServiceLogger `tfsdk:"security_admin_logger"`
	// SystemAdminLogger       tfsdkCTEProfileManagementServiceLogger `tfsdk:"system_admin_logger"`
	// FileSettings            tfsdkCTEProfileFileSettings            `tfsdk:"file_settings"`
	// SyslogSettings          tfsdkCTEProfileSyslogSettings          `tfsdk:"syslog_settings"`
	// UploadSettings          tfsdkCTEProfileUploadSettings          `tfsdk:"upload_settings"`
	// DuplicateSettings       tfsdkCTEProfileDuplicateSettings       `tfsdk:"duplicate_settings"`
	// CacheSettings           tfsdkCTEProfileCacheSettings           `tfsdk:"cache_settings"`
}

type CTEProfilesListJSON struct {
	ID                     string `json:"id"`
	URI                    string `json:"uri"`
	Account                string `json:"account"`
	Application            string `json:"application"`
	CreatedAt              string `json:"created_at"`
	UpdatedAt              string `json:"updated_at"`
	Name                   string `json:"name"`
	Description            string `json:"description"`
	LDTQOSCapCPUAllocation bool   `json:"ldt_qos_cap_cpu_allocation"`
	LDTQOSCapCPUPercent    int64  `json:"ldt_qos_cpu_percent"`
	LDTQOSRekeyOption      string `json:"ldt_qos_rekey_option"`
	LDTQOSRekeyRate        int64  `json:"ldt_qos_rekey_rate"`
	ConciseLogging         bool   `json:"concise_logging"`
	ConnectTimeout         int64  `json:"connect_timeout"`
	LDTQOSSchedule         string `json:"ldt_qos_schedule"`
	LDTQOSStatusCheckRate  int64  `json:"ldt_qos_status_check_rate"`
	MetadataScanInterval   int64  `json:"metadata_scan_interval"`
	MFAExemptUserSetID     string `json:"mfa_exempt_user_set_id"`
	MFAExemptUserSetName   string `json:"mfa_exempt_user_set_name"`
	OIDCConnectionID       string `json:"oidc_connection_id"`
	OIDCConnectionName     string `json:"oidc_connection_name"`
	RWPOperation           string `json:"rwp_operation"`
	RWPProcessSet          string `json:"rwp_process_set"`
	ServerResponseRate     int64  `json:"server_response_rate"`
	// QOSSchedules            []jsonCTEProfileQOSSchedule           `json:"qos_schedules"`
	// ServerSettings          []jsonCTEProfileServiceSetting        `json:"server_settings"`
	// ManagementServiceLogger jsonCTEProfileManagementServiceLogger `json:"management_service_logger"`
	// PolicyEvaluationLogger  jsonCTEProfileManagementServiceLogger `json:"policy_evaluation_logger"`
	// SecurityAdminLogger     jsonCTEProfileManagementServiceLogger `json:"security_admin_logger"`
	// SystemAdminLogger       jsonCTEProfileManagementServiceLogger `json:"system_admin_logger"`
	// FileSettings            jsonCTEProfileFileSettings            `json:"file_settings"`
	// SyslogSettings          jsonCTEProfileSyslogSettings          `json:"syslog_settings"`
	// UploadSettings          jsonCTEProfileUploadSettings          `json:"upload_settings"`
	// DuplicateSettings       jsonCTEProfileDuplicateSettings       `json:"duplicate_settings"`
	// CacheSettings           jsonCTEProfileCacheSettings           `json:"cache_settings"`
}

type CTEResourceSetListItemTFSDK struct {
	Index             types.Int64  `tfsdk:"index"`
	Directory         types.String `tfsdk:"directory"`
	File              types.String `tfsdk:"file"`
	IncludeSubfolders types.Bool   `tfsdk:"include_subfolders"`
	HDFS              types.Bool   `tfsdk:"hdfs"`
}

type CTEResourceSetsListTFSDK struct {
	ID          types.String                  `tfsdk:"id"`
	Name        types.String                  `tfsdk:"name"`
	Description types.String                  `tfsdk:"description"`
	URI         types.String                  `tfsdk:"uri"`
	Account     types.String                  `tfsdk:"account"`
	CreateAt    types.String                  `tfsdk:"created_at"`
	UpdatedAt   types.String                  `tfsdk:"updated_at"`
	Type        types.String                  `tfsdk:"type"`
	Resources   []CTEResourceSetListItemTFSDK `tfsdk:"resources"`
}

type CTEResourceSetsListJSON struct {
	ID          string                       `json:"id"`
	URI         string                       `json:"uri"`
	Account     string                       `json:"account"`
	CreatedAt   string                       `json:"createdAt"`
	Name        string                       `json:"name"`
	UpdatedAt   string                       `json:"updatedAt"`
	Description string                       `json:"description"`
	Type        string                       `json:"type"`
	Resources   []CTEResourceSetListItemJSON `json:"resources"`
}

type CTEResourceSetListItemJSON struct {
	Index             int64  `json:"index"`
	Directory         string `json:"directory"`
	File              string `json:"file"`
	IncludeSubfolders bool   `json:"include_subfolders"`
	HDFS              bool   `json:"hdfs"`
}

type CTESignatureSetsListTFSDK struct {
	ID                 types.String   `tfsdk:"id"`
	URI                types.String   `tfsdk:"uri"`
	Account            types.String   `tfsdk:"account"`
	CreatedAt          types.String   `tfsdk:"created_at"`
	UpdatedAt          types.String   `tfsdk:"updated_at"`
	Name               types.String   `tfsdk:"name"`
	Type               types.String   `tfsdk:"type"`
	Description        types.String   `tfsdk:"description"`
	ReferenceVersion   types.Int64    `tfsdk:"reference_version"`
	SourceList         []types.String `tfsdk:"source_list"`
	SigningStatus      types.String   `tfsdk:"signing_status"`
	PercentageComplete types.Int64    `tfsdk:"percentage_complete"`
	UpdatedBy          types.String   `tfsdk:"updated_by"`
	DockerImgID        types.String   `tfsdk:"docker_img_id"`
	DockerContID       types.String   `tfsdk:"docker_cont_id"`
}

type SignatureSetJSON struct {
	ID                 string   `json:"id"`
	URI                string   `json:"uri"`
	Account            string   `json:"account"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
	Name               string   `json:"name"`
	Type               string   `json:"type"`
	Description        string   `json:"description"`
	ReferenceVersion   int64    `json:"reference_version"`
	SourceList         []string `json:"source_list"`
	SigningStatus      string   `json:"signing_status"`
	PercentageComplete int64    `json:"percentage_complete"`
	UpdatedBy          string   `json:"updated_by"`
	DockerImgID        string   `json:"docker_img_id"`
	DockerContID       string   `json:"docker_cont_id"`
}

type CTEUserSetsListItemTFSDK struct {
	Index    types.Int64  `tfsdk:"index"`
	GID      types.Int64  `tfsdk:"gid"`
	GName    types.String `tfsdk:"gname"`
	OSDomain types.String `tfsdk:"os_domain"`
	UID      types.Int64  `tfsdk:"uid"`
	UName    types.String `tfsdk:"uname"`
}

type CTEUserSetsListTFSDK struct {
	ID          types.String               `tfsdk:"id"`
	Name        types.String               `tfsdk:"name"`
	Description types.String               `tfsdk:"description"`
	URI         types.String               `tfsdk:"uri"`
	Account     types.String               `tfsdk:"account"`
	CreateAt    types.String               `tfsdk:"created_at"`
	UpdatedAt   types.String               `tfsdk:"updated_at"`
	Users       []CTEUserSetsListItemTFSDK `tfsdk:"users"`
}

type CTEUserSetsListJSON struct {
	ID          string                    `json:"id"`
	URI         string                    `json:"uri"`
	Account     string                    `json:"account"`
	CreatedAt   string                    `json:"createdAt"`
	Name        string                    `json:"name"`
	UpdatedAt   string                    `json:"updatedAt"`
	Description string                    `json:"description"`
	Users       []CTEUserSetsListItemJSON `json:"users"`
}

type CTEUserSetsListItemJSON struct {
	Index    int64  `json:"index"`
	GID      int64  `json:"gid"`
	GName    string `json:"gname"`
	OSDomain string `json:"os_domain"`
	UID      int64  `json:"uid"`
	UName    string `json:"uname"`
}

type CTEClientGuardPointParamsTFSDK struct {
	GPType                         types.String `tfsdk:"guard_point_type"`
	PolicyID                       types.String `tfsdk:"policy_id"`
	IsAutomountEnabled             types.Bool   `tfsdk:"automount_enabled"`
	IsCIFSEnabled                  types.Bool   `tfsdk:"cifs_enabled"`
	IsDataClassificationEnabled    types.Bool   `tfsdk:"data_classification_enabled"`
	IsDataLineageEnabled           types.Bool   `tfsdk:"data_lineage_enabled"`
	DiskName                       types.String `tfsdk:"disk_name"`
	DiskgroupName                  types.String `tfsdk:"diskgroup_name"`
	IsEarlyAccessEnabled           types.Bool   `tfsdk:"early_access"`
	IsIntelligentProtectionEnabled types.Bool   `tfsdk:"intelligent_protection"`
	IsDeviceIDTCapable             types.Bool   `tfsdk:"is_idt_capable_device"`
	IsGuardEnabled                 types.Bool   `tfsdk:"guard_enabled"`
	IsMFAEnabled                   types.Bool   `tfsdk:"mfa_enabled"`
	NWShareCredentialsID           types.String `tfsdk:"network_share_credentials_id"`
	PreserveSparseRegions          types.Bool   `tfsdk:"preserve_sparse_regions"`
}

type CTEClientGuardPointTFSDK struct {
	ID               types.String                   `tfsdk:"id"`
	CTEClientID      types.String                   `tfsdk:"client_id"`
	GuardPaths       []types.String                 `tfsdk:"guard_paths"`
	GuardPointParams CTEClientGuardPointParamsTFSDK `tfsdk:"guard_point_params" validate:"required"`
}

type CTEClientGuardPointParamsJSON struct {
	GPType                         string `json:"guard_point_type" validate:"required"`
	PolicyID                       string `json:"policy_id" validate:"required_unless=guard_point_type ransomware"`
	IsAutomountEnabled             bool   `json:"automount_enabled,omitempty"`
	IsCIFSEnabled                  bool   `json:"cifs_enabled,omitempty"`
	IsDataClassificationEnabled    bool   `json:"data_classification_enabled,omitempty"`
	IsDataLineageEnabled           bool   `json:"data_lineage_enabled,omitempty"`
	DiskName                       string `json:"disk_name,omitempty"`
	DiskgroupName                  string `json:"diskgroup_name,omitempty"`
	IsEarlyAccessEnabled           bool   `json:"early_access,omitempty"`
	IsIntelligentProtectionEnabled bool   `json:"intelligent_protection,omitempty"`
	IsDeviceIDTCapable             bool   `json:"is_idt_capable_device,omitempty"`
	IsMFAEnabled                   bool   `json:"mfa_enabled,omitempty"`
	NWShareCredentialsID           string `json:"network_share_credentials_id,omitempty"`
	PreserveSparseRegions          bool   `json:"preserve_sparse_regions,omitempty"`
}

type CTEClientGuardPointJSON struct {
	GuardPaths       []string                       `json:"guard_paths"`
	GuardPointParams *CTEClientGuardPointParamsJSON `json:"guard_point_params" validate:"required"`
}

type UpdateCTEGuardPointTFSDK struct {
	CTEClientID                 types.String `tfsdk:"cte_client_id"`
	GPID                        types.String `tfsdk:"cte_client_gp_id"`
	IsDataClassificationEnabled types.Bool   `tfsdk:"data_classification_enabled"`
	IsDataLineageEnabled        types.Bool   `tfsdk:"data_lineage_enabled"`
	IsGuardEnabled              types.Bool   `tfsdk:"guard_enabled"`
	IsMFAEnabled                types.Bool   `tfsdk:"mfa_enabled"`
	NWShareCredentialsID        types.String `tfsdk:"network_share_credentials_id"`
}

type UpdateCTEGuardPointJSON struct {
	IsDataClassificationEnabled bool   `json:"data_classification_enabled"`
	IsDataLineageEnabled        bool   `json:"data_lineage_enabled"`
	IsGuardEnabled              bool   `json:"guard_enabled"`
	IsMFAEnabled                bool   `json:"mfa_enabled,omitempty"`
	NWShareCredentialsID        string `json:"network_share_credentials_id,omitempty"`
}

type CTEClientGuardPointUnguardJSON struct {
	GuardPointIdList []string `json:"guard_point_id_list" validate:"required"`
}
type CTEClientGroupTFSDK struct {
	ID                      types.String   `tfsdk:"id"`
	ClusterType             types.String   `tfsdk:"cluster_type"`
	Name                    types.String   `tfsdk:"name"`
	CommunicationEnabled    types.Bool     `tfsdk:"communication_enabled"`
	Description             types.String   `tfsdk:"description"`
	LDTDesignatedPrimarySet types.String   `tfsdk:"ldt_designated_primary_set"`
	Password                types.String   `tfsdk:"password"`
	PasswordCreationMethod  types.String   `tfsdk:"password_creation_method"`
	ProfileID               types.String   `tfsdk:"profile_id"`
	ClientLocked            types.Bool     `tfsdk:"client_locked"`
	EnableDomainSharing     types.Bool     `tfsdk:"enable_domain_sharing"`
	EnabledCapabilities     types.String   `tfsdk:"enabled_capabilities"`
	SharedDomainList        []types.String `tfsdk:"shared_domain_list"`
	SystemLocked            types.Bool     `tfsdk:"system_locked"`
	AuthBinaries            types.String   `tfsdk:"auth_binaries"`
	ReSign                  types.Bool     `tfsdk:"re_sign"`
	ClientList              []types.String `tfsdk:"client_list"`
	InheritAttributes       types.Bool     `tfsdk:"inherit_attributes"`
	ClientID                types.String   `tfsdk:"client_id"`
	OpType                  types.String   `tfsdk:op_type`
	Paused                  types.Bool     `tfsdk:"paused"`
}

type CTEClientGroupJSON struct {
	ID                      string   `json:"id"`
	ClusterType             string   `json:"cluster_type"`
	Name                    string   `json:"name"`
	CommunicationEnabled    bool     `json:"communication_enabled"`
	Description             string   `json:"description"`
	LDTDesignatedPrimarySet string   `json:"ldt_designated_primary_set"`
	Password                string   `json:"password,omitempty"`
	PasswordCreationMethod  string   `json:"password_creation_method"`
	ProfileID               string   `json:"profile_id"`
	ClientLocked            bool     `json:"client_locked"`
	EnableDomainSharing     bool     `json:"enable_domain_sharing"`
	EnabledCapabilities     string   `json:"enabled_capabilities"`
	SharedDomainList        []string `json:"shared_domain_list"`
	SystemLocked            bool     `json:"system_locked"`
	AuthBinaries            string   `json:"auth_binaries"`
	ReSign                  bool     `json:"re_sign"`
	ClientList              []string `json:"client_list"`
	InheritAttributes       bool     `json:"inherit_attributes"`
	ClientID                string   `json:"client_id"`
	Paused                  bool     `json:"paused"`
}

type CTECSIGroupTFSDK struct {
	ID            types.String   `tfsdk:"id"`
	Namespace     types.String   `tfsdk:"kubernetes_namespace"`
	StorageClass  types.String   `tfsdk:"kubernetes_storage_class"`
	ClientProfile types.String   `tfsdk:"client_profile"`
	Name          types.String   `tfsdk:"name"`
	Description   types.String   `tfsdk:"description"`
	ClientList    []types.String `tfsdk:"client_list"`
	PolicyList    []types.String `tfsdk:"policy_list"`
	ClientID      types.String   `tfsdk:"client_id"`
	GuardEnabled  types.Bool     `tfsdk:"guard_enabled"`
	GPID          types.String   `tfsdk:"gp_id"`
	OpType        types.String   `tfsdk:"op_type"`
}

type CTECSIGroupJSON struct {
	ID            string   `json:"id"`
	Namespace     string   `json:"k8s_namespace"`
	StorageClass  string   `json:"k8s_storage_class"`
	ClientProfile string   `json:"client_profile"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	ClientList    []string `json:"client_list"`
	PolicyList    []string `json:"policy_list"`
	ClientID      string   `json:"client_id"`
	GuardEnabled  bool     `json:"guard_enabled"`
	GPID          string   `json:"gp_id"`
	OpType        string   `json:"op_type"`
}

type LDTGroupCommSvcTFSDK struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	ClientList  []types.String `tfsdk:"client_list"`
}

type LDTGroupCommSvcJSON struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	ClientList  []string `json:"client_list"`
}

type CTEPolicyAddKeyRuleTFSDK struct {
	CTEClientPolicyID types.String `tfsdk:"policy_id"`
	KeyRuleID         types.String `tfsdk:"rule_id"`
	OrderNumber       types.Int64  `tfsdk:"order_number"`
	KeyRule           KeyRuleTFSDK `tfsdk:"rule"`
}

type CTEPolicyAddLDTKeyRuleTFSDK struct {
	CTEClientPolicyID types.String      `tfsdk:"policy_id"`
	LDTKeyRuleID      types.String      `tfsdk:"rule_id"`
	OrderNumber       types.Int64       `tfsdk:"order_number"`
	LDTKeyRules       []LDTKeyRuleTFSDK `tfsdk:"rule"`
}

type CTEPolicyAddSecurityRuleTFSDK struct {
	CTEClientPolicyID types.String      `tfsdk:"policy_id"`
	SecurityRuleID    types.String      `tfsdk:"rule_id"`
	OrderNumber       types.Int64       `tfsdk:"order_number"`
	SecurityRule      SecurityRuleTFSDK `tfsdk:"rule"`
}

type CTEPolicyAddSignatureRuleTFSDK struct {
	CTEPolicyID      types.String   `tfsdk:"policy_id"`
	SignatureRuleID  types.String   `tfsdk:"id"`
	SignatureSetList []types.String `tfsdk:"signature_set_id_list"`
}

type CTEProcessTFSDK struct {
	Directory     types.String `tfsdk:"directory"`
	File          types.String `tfsdk:"file"`
	Labels        types.Map    `tfsdk:"labels"`
	ResourceSetId types.String `tfsdk:"resource_set_id"`
	Signature     types.String `tfsdk:"signature"`
}

type CTEProcessSetTFSDK struct {
	ID          types.String      `tfsdk:"id"`
	URI         types.String      `tfsdk:"uri"`
	Account     types.String      `tfsdk:"account"`
	Application types.String      `tfsdk:"application"`
	DevAccount  types.String      `tfsdk:"dev_account"`
	CreatedAt   types.String      `tfsdk:"created_at"`
	UpdatedAt   types.String      `tfsdk:"updated_at"`
	Name        types.String      `tfsdk:"name"`
	Description types.String      `tfsdk:"description"`
	Labels      types.Map         `tfsdk:"labels"`
	Processes   []CTEProcessTFSDK `tfsdk:"processes"`
}

type CTEProcessJSON struct {
	Directory     string                 `json:"directory"`
	File          string                 `json:"file"`
	Labels        map[string]interface{} `json:"labels"`
	ResourceSetId string                 `json:"resource_set_id"`
	Signature     string                 `json:"signature"`
}

type CTEProcessSetJSON struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Labels      map[string]interface{} `json:"labels"`
	Processes   []CTEProcessJSON       `json:"processes"`
}

type CTEProfileCacheSettingsTFSDK struct {
	MaxFiles types.Int64 `tfsdk:"max_files"`
	MaxSpace types.Int64 `tfsdk:"max_space"`
}

type CTEProfileDuplicateSettingsTFSDK struct {
	SuppressInterval  types.Int64 `tfsdk:"suppress_interval"`
	SuppressThreshold types.Int64 `tfsdk:"suppress_threshold"`
}

type CTEProfileFileSettingsTFSDK struct {
	AllowPurge    types.Bool   `tfsdk:"allow_purge"`
	FileThreshold types.String `tfsdk:"file_threshold"`
	MaxFileSize   types.Int64  `tfsdk:"max_file_size"`
	MaxOldFiles   types.Int64  `tfsdk:"max_old_files"`
}

type CTEProfileManagementServiceLoggerTFSDK struct {
	Duplicates    types.String `tfsdk:"duplicates"`
	FileEnabled   types.Bool   `tfsdk:"file_enabled"`
	SyslogEnabled types.Bool   `tfsdk:"syslog_enabled"`
	Threshold     types.String `tfsdk:"threshold"`
	UploadEnabled types.Bool   `tfsdk:"upload_enabled"`
}

type CTEProfileQOSScheduleTFSDK struct {
	EndTimeHour   types.Int64  `tfsdk:"end_time_hour"`
	EndTimeMin    types.Int64  `tfsdk:"end_time_min"`
	EndWeekday    types.String `tfsdk:"end_weekday"`
	StartTimeHour types.Int64  `tfsdk:"start_time_hour"`
	StartTimeMin  types.Int64  `tfsdk:"start_time_min"`
	StartWeekday  types.String `tfsdk:"start_weekday"`
}

type CTEProfileServiceSettingTFSDK struct {
	HostName types.String `tfsdk:"host_name"`
	Priority types.Int64  `tfsdk:"priority"`
}

type CTEProfileSyslogSettingServerTFSDK struct {
	CACert        types.String `tfsdk:"ca_certificate"`
	Certificate   types.String `tfsdk:"certificate"`
	MessageFormat types.String `tfsdk:"message_format"`
	Name          types.String `tfsdk:"name"`
	Port          types.Int64  `tfsdk:"port"`
	PrivateKey    types.String `tfsdk:"private_key"`
	Protocol      types.String `tfsdk:"protocol"`
}

type CTEProfileSyslogSettingsTFSDK struct {
	Local     types.Bool                           `tfsdk:"local"`
	Servers   []CTEProfileSyslogSettingServerTFSDK `tfsdk:"servers"`
	Threshold types.String                         `tfsdk:"syslog_threshold"`
}

type CTEProfileUploadSettingsTFSDK struct {
	ConnectionTimeout    types.Int64  `tfsdk:"connection_timeout"`
	DropIfBusy           types.Bool   `tfsdk:"drop_if_busy"`
	JobCompletionTimeout types.Int64  `tfsdk:"job_completion_timeout"`
	MaxInterval          types.Int64  `tfsdk:"max_interval"`
	MaxMessages          types.Int64  `tfsdk:"max_messages"`
	MinInterval          types.Int64  `tfsdk:"min_interval"`
	Threshold            types.String `tfsdk:"upload_threshold"`
}

type CTEProfileTFSDK struct {
	ID                     types.String                            `tfsdk:"id"`
	Name                   types.String                            `tfsdk:"name"`
	CacheSettings          *CTEProfileCacheSettingsTFSDK           `tfsdk:"cache_settings"`
	ConciseLogging         types.Bool                              `tfsdk:"concise_logging"`
	ConnectTimeout         types.Int64                             `tfsdk:"connect_timeout"`
	Description            types.String                            `tfsdk:"description"`
	DuplicateSettings      *CTEProfileDuplicateSettingsTFSDK       `tfsdk:"duplicate_settings"`
	FileSettings           *CTEProfileFileSettingsTFSDK            `tfsdk:"file_settings"`
	Labels                 types.Map                               `tfsdk:"labels"`
	LDTQOSCapCPUAllocation types.Bool                              `tfsdk:"ldt_qos_cap_cpu_allocation"`
	LDTQOSCapCPUPercent    types.Int64                             `tfsdk:"ldt_qos_cpu_percent"`
	LDTQOSRekeyOption      types.String                            `tfsdk:"ldt_qos_rekey_option"`
	LDTQOSRekeyRate        types.Int64                             `tfsdk:"ldt_qos_rekey_rate"`
	LDTQOSSchedule         types.String                            `tfsdk:"ldt_qos_schedule"`
	LDTQOSStatusCheckRate  types.Int64                             `tfsdk:"ldt_qos_status_check_rate"`
	Client_Logging_Config  *CTEProfileManagementServiceLoggerTFSDK `tfsdk:"client_logging_configuration"`
	MetadataScanInterval   types.Int64                             `tfsdk:"metadata_scan_interval"`
	MFAExemptUserSetID     types.String                            `tfsdk:"mfa_exempt_user_set_id"`
	OIDCConnectionID       types.String                            `tfsdk:"oidc_connection_id"`
	QOSSchedules           []CTEProfileQOSScheduleTFSDK            `tfsdk:"qos_schedules"`
	RWPOperation           types.String                            `tfsdk:"rwp_operation"`
	RWPProcessSet          types.String                            `tfsdk:"rwp_process_set"`
	ServerResponseRate     types.Int64                             `tfsdk:"server_response_rate"`
	ServerSettings         []CTEProfileServiceSettingTFSDK         `tfsdk:"server_settings"`
	SyslogSettings         *CTEProfileSyslogSettingsTFSDK          `tfsdk:"syslog_settings"`
	UploadSettings         *CTEProfileUploadSettingsTFSDK          `tfsdk:"upload_settings"`
}

type CTEProfileCacheSettingsJSON struct {
	MaxFiles int64 `json:"max_files,omitempty"`
	MaxSpace int64 `json:"max_space,omitempty"`
}

type CTEProfileDuplicateSettingsJSON struct {
	SuppressInterval  int64 `json:"suppress_interval,omitempty"`
	SuppressThreshold int64 `json:"suppress_threshold,omitempty"`
}

type CTEProfileFileSettingsJSON struct {
	AllowPurge    bool   `json:"allow_purge,omitempty"`
	FileThreshold string `json:"file_threshold,omitempty"`
	MaxFileSize   int64  `json:"max_file_size,omitempty"`
	MaxOldFiles   int64  `json:"max_old_files,omitempty"`
}

type CTEProfileManagementServiceLoggerJSON struct {
	Duplicates    string `json:"duplicates,omitempty"`
	FileEnabled   bool   `json:"file_enabled,omitempty"`
	SyslogEnabled bool   `json:"syslog_enabled,omitempty"`
	Threshold     string `json:"threshold,omitempty"`
	UploadEnabled bool   `json:"upload_enabled,omitempty"`
}

type CTEProfileQOSScheduleJSON struct {
	EndTimeHour   int64  `json:"end_time_hour,omitempty"`
	EndTimeMin    int64  `json:"end_time_min,omitempty"`
	EndWeekday    string `json:"end_weekday,omitempty"`
	StartTimeHour int64  `json:"start_time_hour,omitempty"`
	StartTimeMin  int64  `json:"start_time_min,omitempty"`
	StartWeekday  string `json:"start_weekday,omitempty"`
}

type CTEProfileServiceSettingJSON struct {
	HostName string `json:"hostName,omitempty"`
	Priority int64  `json:"priority,omitempty"`
}

type CTEProfileSyslogSettingServerJSON struct {
	CACert        string `json:"caCertificate,omitempty"`
	Certificate   string `json:"certificate,omitempty"`
	MessageFormat string `json:"message_format,omitempty"`
	Name          string `json:"name,omitempty"`
	Port          int64  `json:"port,omitempty"`
	PrivateKey    string `json:"privateKey,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
}

type CTEProfileSyslogSettingsJSON struct {
	Local     bool                                `json:"local,omitempty"`
	Servers   []CTEProfileSyslogSettingServerJSON `json:"servers,omitempty"`
	Threshold string                              `json:"syslog_threshold,omitempty"`
}

type CTEProfileUploadSettingsJSON struct {
	ConnectionTimeout    int64  `json:"connection_timeout,omitempty"`
	DropIfBusy           bool   `json:"drop_if_busy,omitempty"`
	JobCompletionTimeout int64  `json:"job_completion_timeout,omitempty"`
	MaxInterval          int64  `json:"max_interval,omitempty"`
	MaxMessages          int64  `json:"max_messages,omitempty"`
	MinInterval          int64  `json:"min_interval,omitempty"`
	Threshold            string `json:"upload_threshold,omitempty"`
}

type CTEProfileJSON struct {
	Name                    string                                 `json:"name"`
	CacheSettings           *CTEProfileCacheSettingsJSON           `json:"cache_settings,omitempty"`
	ConciseLogging          bool                                   `json:"concise_logging,omitempty"`
	ConnectTimeout          int64                                  `json:"connect_timeout,omitempty"`
	Description             string                                 `json:"description,omitempty"`
	DuplicateSettings       *CTEProfileDuplicateSettingsJSON       `json:"duplicate_settings,omitempty"`
	FileSettings            *CTEProfileFileSettingsJSON            `json:"file_settings,omitempty"`
	Labels                  map[string]interface{}                 `json:"labels,omitempty"`
	LDTQOSCapCPUAllocation  bool                                   `json:"ldt_qos_cap_cpu_allocation,omitempty"`
	LDTQOSCapCPUPercent     int64                                  `json:"ldt_qos_cpu_percent,omitempty"`
	LDTQOSRekeyOption       string                                 `json:"ldt_qos_rekey_option,omitempty"`
	LDTQOSRekeyRate         int64                                  `json:"ldt_qos_rekey_rate,omitempty"`
	LDTQOSSchedule          string                                 `json:"ldt_qos_schedule,omitempty"`
	LDTQOSStatusCheckRate   int64                                  `json:"ldt_qos_status_check_rate,omitempty"`
	ManagementServiceLogger *CTEProfileManagementServiceLoggerJSON `json:"management_service_logger,omitempty"`
	MetadataScanInterval    int64                                  `json:"metadata_scan_interval,omitempty"`
	MFAExemptUserSetID      string                                 `json:"mfa_exempt_user_set_id,omitempty"`
	OIDCConnectionID        string                                 `json:"oidc_connection_id,omitempty"`
	PolicyEvaluationLogger  *CTEProfileManagementServiceLoggerJSON `json:"policy_evaluation_logger,omitempty"`
	QOSSchedules            *[]CTEProfileQOSScheduleJSON           `json:"qos_schedules,omitempty"`
	RWPOperation            string                                 `json:"rwp_operation,omitempty"`
	RWPProcessSet           string                                 `json:"rwp_process_set,omitempty"`
	SecurityAdminLogger     *CTEProfileManagementServiceLoggerJSON `json:"security_admin_logger,omitempty"`
	ServerResponseRate      int64                                  `json:"server_response_rate,omitempty"`
	ServerSettings          *[]CTEProfileServiceSettingJSON        `json:"server_settings,omitempty"`
	SyslogSettings          *CTEProfileSyslogSettingsJSON          `json:"syslog_settings,omitempty"`
	SystemAdminLogger       *CTEProfileManagementServiceLoggerJSON `json:"system_admin_logger,omitempty"`
	UploadSettings          *CTEProfileUploadSettingsJSON          `json:"upload_settings,omitempty"`
}

type ClassificationTagAttributesTFSDK struct {
	DataType types.String `tfsdk:"data_type"`
	Name     types.String `tfsdk:"name"`
	Operator types.String `tfsdk:"operator"`
	Value    types.String `tfsdk:"value"`
}

type ClassificationTagTFSDK struct {
	Description types.String                       `tfsdk:"description"`
	Name        types.String                       `tfsdk:"name"`
	Attributes  []ClassificationTagAttributesTFSDK `tfsdk:"attributes"`
}

type CTEResourceTFSDK struct {
	Directory         types.String `tfsdk:"directory"`
	File              types.String `tfsdk:"file"`
	HDFS              types.Bool   `tfsdk:"hdfs"`
	IncludeSubfolders types.Bool   `tfsdk:"include_subfolders"`
}

type CTEResourceSetTFSDK struct {
	ID          types.String       `tfsdk:"id"`
	URI         types.String       `tfsdk:"uri"`
	Account     types.String       `tfsdk:"account"`
	Application types.String       `tfsdk:"application"`
	DevAccount  types.String       `tfsdk:"dev_account"`
	CreatedAt   types.String       `tfsdk:"created_at"`
	UpdatedAt   types.String       `tfsdk:"updated_at"`
	Name        types.String       `tfsdk:"name"`
	Description types.String       `tfsdk:"description"`
	Labels      types.Map          `tfsdk:"labels"`
	Resources   []CTEResourceTFSDK `tfsdk:"resources"`
	Type        types.String       `tfsdk:"type"`
	//ClassificationTags []ClassificationTagTFSDK `tfsdk:"classification_tags"`
}

type ClassificationTagAttributesJSON struct {
	DataType string `json:"data_type"`
	Name     string `json:"name"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type ClassificationTagJSON struct {
	Description string                            `json:"description"`
	Name        string                            `json:"name"`
	Attributes  []ClassificationTagAttributesJSON `json:"attributes"`
}

type CTEResourceJSON struct {
	Directory         string `json:"directory"`
	File              string `json:"file"`
	HDFS              bool   `json:"hdfs"`
	IncludeSubfolders bool   `json:"include_subfolders"`
}

type CTEResourceSetJSON struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Labels      map[string]interface{} `json:"labels"`
	Resources   []CTEResourceJSON      `json:"resources"`
	Type        string                 `json:"type"`
	//ClassificationTags []ClassificationTagJSON `json:"classification_tags"`
}

type CTESignatureSetTFSDK struct {
	ID          types.String   `tfsdk:"id"`
	URI         types.String   `tfsdk:"uri"`
	Account     types.String   `tfsdk:"account"`
	Application types.String   `tfsdk:"application"`
	DevAccount  types.String   `tfsdk:"dev_account"`
	CreatedAt   types.String   `tfsdk:"created_at"`
	UpdatedAt   types.String   `tfsdk:"updated_at"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Labels      types.Map      `tfsdk:"labels"`
	Type        types.String   `tfsdk:"type"`
	Sources     []types.String `tfsdk:"source_list"`
}

type CTESignatureSetJSON struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Labels      map[string]interface{} `json:"labels"`
	Type        string                 `json:"type"`
	Sources     []string               `json:"source_list"`
}

type CTEUserTFSDK struct {
	GID      types.Int64  `tfsdk:"gid"`
	GName    types.String `tfsdk:"gname"`
	OSDomain types.String `tfsdk:"os_domain"`
	UID      types.Int64  `tfsdk:"uid"`
	UName    types.String `tfsdk:"uname"`
}

type CTEUserSetTFSDK struct {
	ID          types.String   `tfsdk:"id"`
	URI         types.String   `tfsdk:"uri"`
	Account     types.String   `tfsdk:"account"`
	Application types.String   `tfsdk:"application"`
	DevAccount  types.String   `tfsdk:"dev_account"`
	CreatedAt   types.String   `tfsdk:"created_at"`
	UpdatedAt   types.String   `tfsdk:"updated_at"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Labels      types.Map      `tfsdk:"labels"`
	Users       []CTEUserTFSDK `tfsdk:"users"`
}

type CTEUserJSON struct {
	GID      int    `json:"gid"`
	GName    string `json:"gname"`
	OSDomain string `json:"os_domain"`
	UID      int    `json:"uid"`
	UName    string `json:"uname"`
}
