package models

import (
	"encoding/json"
)

// All JSON request and response structs of the Azure certificate API.

// AzureRestoreCertificatePayloadJSON is the body of POST /azure/certificates/:id/restore.
type AzureRestoreCertificatePayloadJSON struct {
	KeyVault string `json:"key_vault"`
}

// AzureCertificateCreateJSON is the body of POST /azure/certificates.
type AzureCertificateCreateJSON struct {
	CertName   string                    `json:"cert_name"`
	KeyVault   string                    `json:"key_vault"`
	AzureParam AzureCertificateParamJSON `json:"azure_param"`
}

// AzureCertificateImportJSON is the body of POST /azure/certificates/import.
type AzureCertificateImportJSON struct {
	CertName      string                     `json:"cert_name"`
	KeyVault      string                     `json:"key_vault"`
	CaID          string                     `json:"caid,omitempty"`
	SourceCertID  string                     `json:"source_cert_identifier,omitempty"`
	Certificate   string                     `json:"certificate,omitempty"`
	PrivateKeyPem string                     `json:"private_key_pem,omitempty"`
	Password      string                     `json:"password,omitempty"`
	AzureParam    *AzureCertificateParamJSON `json:"azure_param,omitempty"`
}

type AzureCertificateParamJSON struct {
	Policy *AzureCertificatePolicyJSON `json:"policy,omitempty"`
	Tags   map[string]string           `json:"tags,omitempty"`
}

type AzureCertificatePolicyJSON struct {
	Issuer          *AzureCertificateIssuerJSON          `json:"issuer,omitempty"`
	KeyProps        *AzureCertificateKeyPropsJSON        `json:"key_props,omitempty"`
	X509Props       *AzureCertificateX509PropsJSON       `json:"x509_props,omitempty"`
	Attributes      *AzureCertificateAttributesJSON      `json:"attributes,omitempty"`
	LifetimeActions []AzureCertificateLifetimeActionJSON `json:"lifetime_actions,omitempty"`
	SecretProps     *AzureCertificateSecretPropsJSON     `json:"secret_props,omitempty"`
}

type AzureCertificateIssuerJSON struct {
	Name             string `json:"name"`
	CertificateType  string `json:"cty,omitempty"`
	CertTransparency *bool  `json:"cert_transparency,omitempty"`
}

type AzureCertificateKeyPropsJSON struct {
	Kty        string `json:"kty"`
	Crv        string `json:"crv,omitempty"`
	Exportable *bool  `json:"exportable,omitempty"`
	KeySize    *int64 `json:"key_size,omitempty"`
	ReuseKey   *bool  `json:"reuse_key,omitempty"`
}

type AzureCertificateX509PropsJSON struct {
	Subject          string                    `json:"subject"`
	EnhancedKeyUsage []string                  `json:"ekus,omitempty"`
	KeyUsage         []string                  `json:"key_usage,omitempty"`
	Sans             *AzureCertificateSansJSON `json:"sans,omitempty"`
	ValidityMonths   *int64                    `json:"validity_months,omitempty"`
}

type AzureCertificateSansJSON struct {
	DNSNames []string `json:"dns_names,omitempty"`
	Emails   []string `json:"emails,omitempty"`
	Upns     []string `json:"upns,omitempty"`
}

type AzureCertificateAttributesJSON struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Nbf     *int64 `json:"nbf,omitempty"`
	Exp     *int64 `json:"exp,omitempty"`
}

type AzureCertificateLifetimeActionJSON struct {
	Trigger *AzureCertificateTriggerJSON `json:"trigger,omitempty"`
	Action  *AzureCertificateActionJSON  `json:"action,omitempty"`
}

type AzureCertificateTriggerJSON struct {
	LifetimePercentage *int64 `json:"lifetime_percentage,omitempty"`
	DaysBeforeExpiry   *int64 `json:"days_before_expiry,omitempty"`
}

type AzureCertificateActionJSON struct {
	ActionType string `json:"action_type"`
}

type AzureCertificateSecretPropsJSON struct {
	ContentType string `json:"content_type,omitempty"`
}

// AzureCertificateListPageJSON is the list-response envelope from GET /azure/certificates.
type AzureCertificateListPageJSON struct {
	Total     int64             `json:"total"`
	Resources []json.RawMessage `json:"resources"`
}

// AzureCertificateJSON is a certificate returned by CipherTrust Manager (AzureCertificateDetailed).
// lifetime_actions and sans are held raw because the server stores them as JSONB.
type AzureCertificateJSON struct {
	ID                     string  `json:"id"`
	CreatedAt              string  `json:"createdAt"`
	UpdatedAt              string  `json:"updatedAt"`
	SyncedAt               string  `json:"synced_at"`
	RotatedAt              string  `json:"rotated_at"`
	CertName               string  `json:"cert_name"`
	KeyVault               string  `json:"key_vault"`
	KeyVaultID             string  `json:"key_vault_id"`
	CloudName              string  `json:"cloud_name"`
	Region                 string  `json:"region"`
	Tenant                 string  `json:"tenant"`
	Status                 string  `json:"status"`
	Version                string  `json:"version"`
	VersionCount           int64   `json:"version_count"`
	Operation              string  `json:"operation"`
	OperationError         string  `json:"operation_error"`
	Error                  string  `json:"error"`
	Deleted                bool    `json:"deleted"`
	Gone                   bool    `json:"gone"`
	CertSoftDeletedInAzure bool    `json:"cert_soft_deleted_in_azure"`
	SoftDeleteEnabled      bool    `json:"soft_delete_enabled"`
	CertMaterialOrigin     string  `json:"cert_material_origin"`
	CertSource             string  `json:"cert_source"`
	Backup                 *string `json:"backup"`
	BackupAt               string  `json:"backup_at"`
	AzureCreatedAt         string  `json:"azure_created_at"`
	AzureUpdatedAt         string  `json:"azure_updated_at"`
	AzureExpireAt          string  `json:"azure_expire_at"`

	AzureParam AzureCertificateParamResponseJSON `json:"azure_param"`
}

// AzureCertificateParamResponseJSON is the flattened Azure certificate bundle in a response.
type AzureCertificateParamResponseJSON struct {
	Cert             string                             `json:"cert"`
	Cid              string                             `json:"cid"`
	Kid              string                             `json:"kid"`
	Sid              string                             `json:"sid"`
	X5t              string                             `json:"x5t"`
	LifetimeActions  json.RawMessage                    `json:"lifetime_actions"`
	Crv              string                             `json:"crv"`
	Exportable       bool                               `json:"exportable"`
	KeySize          int64                              `json:"key_size"`
	Kty              string                             `json:"kty"`
	ReuseKey         bool                               `json:"reuse_key"`
	ContentType      string                             `json:"content_type"`
	EnhancedKeyUsage []string                           `json:"ekus"`
	KeyUsage         []string                           `json:"key_usage"`
	Sans             json.RawMessage                    `json:"sans"`
	Subject          string                             `json:"subject"`
	ValidityMonths   int64                              `json:"validity_months"`
	IssuerName       string                             `json:"issuer_name"`
	CertificateType  string                             `json:"cty"`
	CertTransparency bool                               `json:"cert_transparency"`
	Attributes       AzureCertificateAttributesRespJSON `json:"attributes"`
	Tags             map[string]string                  `json:"tags"`
}

// AzureCertificateAttributesRespJSON is the certificate attributes in a response.
type AzureCertificateAttributesRespJSON struct {
	Enabled         *bool  `json:"enabled"`
	Exp             int64  `json:"exp"`
	Nbf             int64  `json:"nbf"`
	RecoverableDays int64  `json:"recoverable_days"`
	RecoveryLevel   string `json:"recovery_level"`
}
