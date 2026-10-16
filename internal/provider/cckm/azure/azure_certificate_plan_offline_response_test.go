package cckm

import (
	"encoding/json"
	"testing"
)

// azureCertOfflineParam is the azure_param part of a fake GET /azure/certificates/:id response.
func azureCertOfflineParam(kind string) map[string]interface{} {
	param := map[string]interface{}{
		"cert":            "base64cert",
		"cid":             "https://vault.example.net/certificates/" + azureCertOfflineName,
		"kid":             "https://vault.example.net/keys/" + azureCertOfflineName + "/v1",
		"sid":             "https://vault.example.net/secrets/" + azureCertOfflineName + "/v1",
		"x5t":             "thumbprint",
		"kty":             "RSA",
		"key_size":        2048,
		"exportable":      true,
		"issuer_name":     "Self",
		"subject":         azureCertOfflineSubject,
		"validity_months": 12,
		"sans":            map[string]interface{}{},
		"tags":            map[string]string{"purpose": "native-test"},
		"attributes": map[string]interface{}{
			"created":          1791873387,
			"enabled":          true,
			"exp":              1823409387,
			"nbf":              1791872787,
			"recoverable_days": 7,
			"recovery_level":   "CustomizedRecoverable",
			"updated":          1791873387,
		},
		"ekus":         []string{"1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"},
		"key_usage":    []string{"digitalSignature", "keyEncipherment"},
		"content_type": "application/x-pkcs12",
		"lifetime_actions": []interface{}{map[string]interface{}{
			"trigger": map[string]interface{}{"lifetime_percentage": 80},
			"action":  map[string]interface{}{"action_type": "AutoRenew"},
		}},
	}
	if kind == azureCertOfflineKindRich {
		// Azure may return list values in a different order than they were configured.
		param["ekus"] = []string{"1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"}
		param["sans"] = map[string]interface{}{"dns_names": []string{"b.example.com", "a.example.com"}}
	}
	if kind == azureCertOfflineKindBare {
		delete(param, "ekus")
		delete(param, "key_usage")
		delete(param, "lifetime_actions")
		delete(param, "content_type")
	}
	return param
}

// azureCertOfflineResponse is a fake GET /azure/certificates/:id response.
func azureCertOfflineResponse(t *testing.T, kind string) string {
	t.Helper()
	response := map[string]interface{}{
		"id":                         "22222222-3333-4444-5555-666666666666",
		"createdAt":                  "2026-10-13T10:00:00.000000Z",
		"updatedAt":                  "2026-10-13T10:00:01.000000Z",
		"synced_at":                  "2026-10-13T10:00:02.000000Z",
		"uri":                        "kylo:kylo:cckm:azure-cert:tf-native-offline-22222222-3333-4444-5555-666666666666",
		"account":                    "kylo:kylo:admin:accounts:kylo",
		"backup":                     "backupvalue",
		"backup_at":                  "2026-10-13T10:00:05.000000Z",
		"deleted":                    false,
		"gone":                       false,
		"cert_soft_deleted_in_azure": false,
		"cert_name":                  azureCertOfflineName,
		"key_vault":                  "vault-name",
		"key_vault_id":               azureCertOfflineVaultID,
		"cloud_name":                 "AzureCloud",
		"region":                     "eastus",
		"tenant":                     "tenant-id",
		"status":                     "AVAILABLE",
		"version":                    "v1",
		"version_count":              1,
		"soft_delete_enabled":        true,
		"cert_material_origin":       "native",
		"cert_source":                "native",
		"azure_created_at":           "2026-10-13T10:00:00Z",
		"azure_updated_at":           "2026-10-13T10:00:00Z",
		"azure_expire_at":            "2027-10-13T10:00:00Z",
		"azure_param":                azureCertOfflineParam(kind),
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal fake response: %v", err)
	}
	return string(body)
}
