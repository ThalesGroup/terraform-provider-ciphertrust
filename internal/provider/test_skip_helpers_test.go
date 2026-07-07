package provider

import (
	"os"
	"testing"
)

// envCDSPaaS is the environment variable the test pipeline sets to indicate the
// target is a CDSPaaS instance rather than on-prem CipherTrust Manager.
// Tests that exercise resources unavailable on CDSPaaS use RequireCM to skip
// themselves cleanly when this is set.
const envCDSPaaS = "CDSPAAS"

// RequireCM marks the calling test as on-prem CipherTrust-Manager-only.
// When the test pipeline runs against a CDSPaaS instance (CDSPAAS=true), the
// test is skipped instead of failing on a "Resource not supported on CDSPaaS"
// diagnostic from the provider.
//
// Call as the first line of any test that exercises a resource gated by
// common.ValidateCMOnly (e.g. ciphertrust_ntp, ciphertrust_syslog,
// ciphertrust_trial_license, ciphertrust_hsm_root_of_trust_setup).
func RequireCM(t *testing.T) {
	t.Helper()
	if os.Getenv(envCDSPaaS) == "true" {
		t.Skipf("skipping %s: resource is CipherTrust-Manager-only, not available on CDSPaaS", t.Name())
	}
}

// RequireCDSPaaS is the inverse of RequireCM: skip the test unless the pipeline
// is targeting a CDSPaaS instance. Reserved for future CDSPaaS-only
// resources; currently unused but present for symmetry.
func RequireCDSPaaS(t *testing.T) {
	t.Helper()
	if os.Getenv(envCDSPaaS) != "true" {
		t.Skipf("skipping %s: test is CDSPaaS-only", t.Name())
	}
}
