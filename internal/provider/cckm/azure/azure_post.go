package cckm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
)

const (
	// azureOpSleep is the number of seconds to wait between retries of an
	// operation that returned a 409 conflict while Azure completes a state transition.
	azureOpSleep = 20
	// azureDefaultOperationTimeout is used when the provider timeout is not set.
	azureDefaultOperationTimeout = 240
)

// azurePostDataV2WithRetry posts payload to endpoint. It is shared by all Azure resources
// (keys, certificates, secrets). A 409 conflict is retried every azureOpSleep seconds
// until azure_operation_timeout is used up or ctx is cancelled.
// Any other error is returned immediately.
func azurePostDataV2WithRetry(ctx context.Context, id string, client *common.Client, endpoint string, payload []byte) (string, error) {
	response, err := client.PostDataV2(ctx, id, endpoint, payload)
	// Retries are limited by azure_operation_timeout, or the default when it is not set.
	timeout := client.CCKMConfig.AzureOperationTimeout
	if timeout <= 0 {
		timeout = azureDefaultOperationTimeout
	}
	maxRetries := timeout / azureOpSleep
	// The client error text carries the status code, so a 409 is detected by matching it.
	for attempt := int64(1); err != nil && strings.Contains(err.Error(), "status: 409") && attempt <= maxRetries; attempt++ {
		client.Log.Info(fmt.Sprintf("[azure_post.go -> azurePostDataV2WithRetry][%s] Conflict on %s, retry %d of %d in %d seconds",
			id, endpoint, attempt, maxRetries, azureOpSleep))
		// Wait between retries, returning as soon as ctx is cancelled.
		timer := time.NewTimer(azureOpSleep * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", fmt.Errorf("operation cancelled while waiting to retry %s: %s", endpoint, ctx.Err().Error())
		case <-timer.C:
		}
		response, err = client.PostDataV2(ctx, id, endpoint, payload)
	}
	return response, err
}

// azurePostNoDataWithRetry posts an empty body to endpoint. A 409 conflict is retried every
// azureOpSleep seconds until azure_operation_timeout is used up or ctx is cancelled.
// Any other error is returned immediately.
func azurePostNoDataWithRetry(ctx context.Context, id string, client *common.Client, endpoint string) (string, error) {
	response, err := client.PostNoData(ctx, id, endpoint)
	timeout := client.CCKMConfig.AzureOperationTimeout
	if timeout <= 0 {
		timeout = azureDefaultOperationTimeout
	}
	maxRetries := timeout / azureOpSleep
	for attempt := int64(1); err != nil && strings.Contains(err.Error(), "status: 409") && attempt <= maxRetries; attempt++ {
		client.Log.Info(fmt.Sprintf("[azure_post.go -> azurePostNoDataWithRetry][%s] Conflict on %s, retry %d of %d in %d seconds",
			id, endpoint, attempt, maxRetries, azureOpSleep))
		timer := time.NewTimer(azureOpSleep * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", fmt.Errorf("operation cancelled while waiting to retry %s: %s", endpoint, ctx.Err().Error())
		case <-timer.C:
		}
		response, err = client.PostNoData(ctx, id, endpoint)
	}
	return response, err
}

// azureUpdateDataV2WithRetry sends a PATCH to endpoint/id. A 409 conflict is retried every
// azureOpSleep seconds until azure_operation_timeout is used up or ctx is cancelled.
// Any other error is returned immediately.
func azureUpdateDataV2WithRetry(ctx context.Context, id string, client *common.Client, endpoint string, keyID string, payload []byte) (string, error) {
	response, err := client.UpdateDataV2(ctx, keyID, endpoint, payload)
	timeout := client.CCKMConfig.AzureOperationTimeout
	if timeout <= 0 {
		timeout = azureDefaultOperationTimeout
	}
	maxRetries := timeout / azureOpSleep
	for attempt := int64(1); err != nil && strings.Contains(err.Error(), "status: 409") && attempt <= maxRetries; attempt++ {
		client.Log.Info(fmt.Sprintf("[azure_post.go -> azureUpdateDataV2WithRetry][%s] Conflict on %s/%s, retry %d of %d in %d seconds",
			id, endpoint, keyID, attempt, maxRetries, azureOpSleep))
		timer := time.NewTimer(azureOpSleep * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", fmt.Errorf("operation cancelled while waiting to retry %s/%s: %s", endpoint, keyID, ctx.Err().Error())
		case <-timer.C:
		}
		response, err = client.UpdateDataV2(ctx, keyID, endpoint, payload)
	}
	return response, err
}
