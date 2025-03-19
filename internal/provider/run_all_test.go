package provider

import (
	"os"
	"testing"
)

func TestAll(t *testing.T) {
	// Ensure acceptance tests are enabled
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("Acceptance tests skipped unless env 'TF_ACC' set")
	}

	// Run tests in the desired order
	t.Run("TestResourceTrialLicense", TestResourceTrialLicense)
	t.Run("TestResourceCMPrometheus", TestResourceCMPrometheus)
	t.Run("TestCiphertrustCMPrometheusDataSource", TestCiphertrustCMPrometheusDataSource)
	t.Run("TestCiphertrustSCPConnectionDataSource", TestCiphertrustSCPConnectionDataSource)
	t.Run("TestResourceCMGroup", TestResourceCMGroup)
	t.Run("TestResourceCMKey", TestResourceCMKey)
	t.Run("TestResourceCMRegToken", TestResourceCMRegToken)
	t.Run("TestResourceCMUser", TestResourceCMUser)
	t.Run("TestResourceCTEPolicyDataTXRule", TestResourceCTEPolicyDataTXRule)
	t.Run("TestResourceCTEProcessSet", TestResourceCTEProcessSet)
	t.Run("TestResourceCTEResourceSet", TestResourceCTEResourceSet)
	t.Run("TestResourceCTESignatureSet", TestResourceCTESignatureSet)
	t.Run("TestResourceCTEUserSet", TestResourceCTEUserSet)
	t.Run("TestResourceCMNTP", TestResourceCMNTP)
	t.Run("TestResourceScheduler", TestResourceScheduler)
	t.Run("TestSchedulerDataSource", TestSchedulerDataSource)
	t.Run("TestResourceSyslog", TestResourceSyslog)
	t.Run("TestResourceCMSCPConnection", TestResourceCMSCPConnection)
	t.Run("TestResourceCTEPolicy", TestResourceCTEPolicy)
	t.Run("TestResourceCMDomain", TestResourceCMDomain)
	t.Run("TestResourceCMProperty", TestResourceCMProperty)
	t.Run("TestResourceCMPolicy", TestResourceCMPolicy)
	t.Run("TestResourceCMPolicyAttachment", TestResourceCMPolicyAttachment)
	//t.Run("TestResourceCMPassordPolicy", TestResourceCMPassordPolicy)
}
