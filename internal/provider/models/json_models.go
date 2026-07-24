package models

// CipherTrust Manager Key Management related attributes

type jsonCMRegTokensListModel struct {
	ID                string `json:"id"`
	URI               string `json:"uri"`
	Account           string `json:"account"`
	Application       string `json:"application"`
	DevAccount        string `json:"devAccount"`
	CreatedAt         string `json:"createdAt"`
	UpdatedAt         string `json:"updatedAt"`
	Token             string `json:"token"`
	ValidUntil        string `json:"valid_until"`
	MaxClients        int64  `json:"max_clients"`
	ClientsRegistered int64  `json:"clients_registered"`
	CAID              string `json:"ca_id"`
	NamePrefix        string `json:"name_prefix"`
}

// type jsonCMKeysListModel struct {
// 	ID               string `json:"id"`
// 	URI              string `json:"uri"`
// 	Account          string `json:"account"`
// 	Application      string `json:"application"`
// 	DevAccount       string `json:"devAccount"`
// 	CreateAt         string `json:"createdAt"`
// 	Name             string `json:"name"`
// 	UpdatedAt        string `json:"updatedAt"`
// 	UsageMask        int64  `json:"usageMask"`
// 	Version          int64  `json:"version"`
// 	Algorithm        string `json:"algorithm"`
// 	Size             int64  `json:"size"`
// 	Format           string `json:"format"`
// 	Unexportable     bool   `json:"unexportable"`
// 	Undeletable      bool   `json:"undeletable"`
// 	ObjectType       string `json:"objectType"`
// 	ActivationDate   string `json:"activationDate"`
// 	DeactivationDate string `json:"deactivationDate"`
// 	ArchiveDate      string `json:"archiveDate"`
// 	DestroyDate      string `json:"destroyDate"`
// 	RevocationReason string `json:"revocationReason"`
// 	State            string `json:"state"`
// 	UUID             string `json:"uuid"`
// 	Description      string `json:"description"`
// }

// CipherTrust Manager Key Management related attributes - END

// We might not need the below struct
// type KeyJSON struct {
// 	KeyID            string `json:"id"`
// 	URI              string `json:"uri"`
// 	Account          string `json:"account"`
// 	Application      string `json:"application"`
// 	DevAccount       string `json:"devAccount"`
// 	CreatedAt        string `json:"createdAt"`
// 	UpdatedAt        string `json:"updatedAt"`
// 	UsageMask        int64  `json:"usageMask"`
// 	Version          int64  `json:"version"`
// 	Algorithm        string `json:"algorithm"`
// 	Size             int64  `json:"size"`
// 	Format           string `json:"format"`
// 	Exportable       bool   `json:"unexportable"`
// 	Deletable        bool   `json:"undeletable"`
// 	ObjectType       string `json:"objectType"`
// 	ActivationDate   string `json:"activationDate"`
// 	DeactivationDate string `json:"deactivationDate"`
// 	ArchiveDate      string `json:"archiveDate"`
// 	DestroyDate      string `json:"destroyDate"`
// 	RevocationReason string `json:"revocationReason"`
// 	State            string `json:"state"`
// 	UUID             string `json:"uuid"`
// 	Description      string `json:"description"`
// 	Name             string `json:"name"`
// }

// type jsonAddDataTXRulePolicy struct {
// 	CTEClientPolicyID string         `json:"policy_id"`
// 	DataTXRuleID      string         `json:"rule_id"`
// 	DataTXRule        DataTxRuleJSON `json:"rule"`
// }

// type jsonAddKeyRulePolicy struct {
// 	CTEClientPolicyID string      `json:"policy_id"`
// 	KeyRuleID         string      `json:"rule_id"`
// 	KeyRule           KeyRuleJSON `json:"rule"`
// }

// type jsonAddLDTKeyRulePolicy struct {
// 	CTEClientPolicyID string      `json:"policy_id"`
// 	LDTKeyRuleID      string      `json:"rule_id"`
// 	LDTKeyRule        LDTRuleJSON `json:"rule"`
// }

// type jsonAddSecurityRulePolicy struct {
// 	CTEClientPolicyID string           `json:"policy_id"`
// 	SecurityRuleID    string           `json:"rule_id"`
// 	SecurityRule      SecurityRuleJSON `json:"rule"`
// }

// type jsonAddSignatureRulePolicy struct {
// 	CTEClientPolicyID string            `json:"policy_id"`
// 	SignatureRuleID   string            `json:"rule_id"`
// 	SignatureRule     SignatureRuleJSON `json:"rule"`
// }

// CTE Profile

// CCKM Models
