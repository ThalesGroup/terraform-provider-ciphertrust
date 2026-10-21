package models

// All JSON request and response structs of the Azure secret API.

// AzureRestoreSecretPayloadJSON is the body of POST /azure/secrets/:id/restore.
type AzureRestoreSecretPayloadJSON struct {
	KeyVault string `json:"key_vault"`
}

// AzureSecretCreateJSON is the body of POST /azure/secrets.
type AzureSecretCreateJSON struct {
	SecretName string               `json:"secret_name"`
	KeyVault   string               `json:"key_vault"`
	AzureParam AzureSecretParamJSON `json:"azure_param"`
}

// AzureSecretParamJSON is the azure_param of a create request. The request uses contentType while the
// response uses content_type.
type AzureSecretParamJSON struct {
	Value       string                     `json:"value"`
	ContentType string                     `json:"contentType,omitempty"`
	Tags        map[string]string          `json:"tags,omitempty"`
	Attributes  *AzureSecretAttributesJSON `json:"attributes,omitempty"`
}

// AzureSecretAttributesJSON holds the attributes of a create or update request. Nbf and Exp are Unix epoch
// seconds.
type AzureSecretAttributesJSON struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Nbf     *int64 `json:"nbf,omitempty"`
	Exp     *int64 `json:"exp,omitempty"`
}

// AzureSecretUpdateJSON is the body of PATCH /azure/secrets/:id. Tags is a pointer so that an empty map is
// sent and clears the tags.
type AzureSecretUpdateJSON struct {
	Attributes  *AzureSecretAttributesJSON `json:"attributes,omitempty"`
	Tags        *map[string]string         `json:"tags,omitempty"`
	ContentType *string                    `json:"contentType,omitempty"`
}

// AzureSecretJSON is an Azure secret in a response. The secret value is deliberately not modelled, it is
// never read back.
type AzureSecretJSON struct {
	ID                       string  `json:"id"`
	URI                      string  `json:"uri"`
	Account                  string  `json:"account"`
	CreatedAt                string  `json:"createdAt"`
	UpdatedAt                string  `json:"updatedAt"`
	SyncedAt                 string  `json:"syncedAt"`
	CreatedBy                string  `json:"created_by"`
	ModifiedBy               string  `json:"modified_by"`
	SecretName               string  `json:"secret_name"`
	KeyVault                 string  `json:"key_vault"`
	KeyVaultID               string  `json:"key_vault_id"`
	CloudName                string  `json:"cloud_name"`
	Region                   string  `json:"region"`
	Tenant                   string  `json:"tenant"`
	Status                   string  `json:"status"`
	Version                  string  `json:"version"`
	VersionCount             int64   `json:"version_count"`
	Deleted                  bool    `json:"deleted"`
	Gone                     bool    `json:"gone"`
	SecretSoftDeletedInAzure bool    `json:"secret_soft_deleted_in_azure"`
	SoftDeleteEnabled        bool    `json:"soft_delete_enabled"`
	Backup                   *string `json:"backup"`
	BackupAt                 string  `json:"backup_at"`
	AzureCreatedAt           string  `json:"azure_created_at"`
	AzureUpdatedAt           string  `json:"azure_updated_at"`

	AzureParam AzureSecretParamResponseJSON `json:"azure_param"`
}

// AzureSecretParamResponseJSON is the azure_param of a response.
type AzureSecretParamResponseJSON struct {
	SecretID    string                        `json:"secret_id"`
	ContentType string                        `json:"content_type"`
	Tags        map[string]string             `json:"tags"`
	Attributes  AzureSecretAttributesRespJSON `json:"attributes"`
}

// AzureSecretAttributesRespJSON is the secret attributes in a response.
type AzureSecretAttributesRespJSON struct {
	Enabled         *bool  `json:"enabled"`
	Nbf             int64  `json:"nbf"`
	Exp             int64  `json:"exp"`
	RecoverableDays int64  `json:"recoverable_days"`
	RecoveryLevel   string `json:"recovery_level"`
}
