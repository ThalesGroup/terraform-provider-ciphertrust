package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	cmHost = "https://ec2-44-205-177-172.compute-1.amazonaws.com"
	keyID  = "f11dd172f3ee4632ad55bb4834bcb95a4a73384647474fa3993bbab4862c7849"
)

func main() {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}

	// Get token
	authBody := `{"grant_type":"password","username":"admin","password":"Koala2.20","domain":"root","auth_domain":"root"}`
	req, _ := http.NewRequest("POST", cmHost+"/api/v1/auth/tokens", bytes.NewBufferString(authBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "auth error:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tokenResp map[string]interface{}
	json.Unmarshal(body, &tokenResp)
	token, _ := tokenResp["jwt"].(string)
	fmt.Printf("Token obtained: %s...\n", token[:min(20, len(token))])

	// Query the key
	req2, _ := http.NewRequest("GET", cmHost+"/api/v1/vault/keys2/"+keyID, nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Fprintln(os.Stderr, "key query error:", err)
		os.Exit(1)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	var keyData map[string]interface{}
	json.Unmarshal(body2, &keyData)

	fmt.Println("\n=== CM API Response for key ===")
	fmt.Printf("id                : %v\n", keyData["id"])
	fmt.Printf("name              : %v\n", keyData["name"])
	fmt.Printf("state             : %v\n", keyData["state"])
	fmt.Printf("revocationReason  : %v\n", keyData["revocationReason"])
	fmt.Printf("revocationMessage : %v\n", keyData["revocationMessage"])

	fmt.Println("\n=== What Terraform config specified ===")
	fmt.Println("revocation_reason  = 'KeyCompromise'")
	fmt.Println("revocation_message = 'test-repro-message-TFIN-286'")

	reason := fmt.Sprintf("%v", keyData["revocationReason"])
	message := fmt.Sprintf("%v", keyData["revocationMessage"])

	fmt.Println("\n=== Analysis ===")
	if reason == "test-repro-message-TFIN-286" && message == "KeyCompromise" {
		fmt.Println("BUG CONFIRMED: revocationReason and revocationMessage are SWAPPED in CM!")
		fmt.Printf("  CM revocationReason  = '%s' (should be 'KeyCompromise')\n", reason)
		fmt.Printf("  CM revocationMessage = '%s' (should be 'test-repro-message-TFIN-286')\n", message)
	} else if reason == "KeyCompromise" && message == "test-repro-message-TFIN-286" {
		fmt.Println("NO BUG: values are correctly stored.")
	} else {
		fmt.Printf("UNEXPECTED: reason=%q, message=%q\n", reason, message)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
