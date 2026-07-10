package cckm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ociErrThrottled is the OCI error code for transient rate-throttle responses (HTTP 429).
// "TooManyRequests" is injected into the error body by OCI itself; CCKM passes it through
// unchanged. Checking only this string (and not the HTTP status code) makes the predicate
// robust against any future CCKM formatting changes to how the status code is reported.
// ociVaultStateConflictError can occur after an operation like restoring a key from backup
// The vault state is in a state of "restoring" for a short period and some operations can fail as a result
const (
	ociErrThrottled            = "TooManyRequests"
	ociVaultStateConflictError = "Vault must be in one of the following states"
	ociMaxRetries              = 4
)

// isOCIThrottleError returns true when the OCI error message contains "TooManyRequests",
// which is the OCI-originated error code for transient rate throttling.
// Other OCI 429 responses (e.g. tenant key quota exceeded) use a different OCI error code
// and will NOT contain "TooManyRequests", so they are correctly excluded from retry.
func isOCIThrottleError(err error) bool {
	return strings.Contains(err.Error(), ociErrThrottled)
}

func isOCIVaultStateConflictError(err error) bool {
	return strings.Contains(err.Error(), ociVaultStateConflictError)
}

// ociPostNoDataWithRetry calls client.PostNoData and retries up to ociMaxRetries times
// when the error is an OCI throttling (TooManyRequests) response.
// Non-throttle errors are returned immediately without retrying.
// Successive waits follow an exponential backoff: 500 ms, 1 s, 2 s, 4 s.
// A warning is logged on every throttled attempt and after all retries are exhausted.
func ociPostNoDataWithRetry(
	ctx context.Context,
	client *common.Client,
	id string,
	endpoint string,
) (string, error) {
	var lastErr error
	for i := 0; i < ociMaxRetries; i++ {
		resp, err := client.PostNoData(ctx, id, endpoint)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		throttled := isOCIThrottleError(err)
		vaultStateConflict := isOCIVaultStateConflictError(err)
		if !throttled && !vaultStateConflict {
			return "", err
		}
		sleep := time.Duration(500*(1<<i)) * time.Millisecond
		if throttled {
			tflog.Warn(ctx, fmt.Sprintf(
				"[OCI retry] PostNoData throttled on attempt %d/%d, sleeping %s, endpoint: %s, error: %s",
				i+1, ociMaxRetries, sleep, endpoint, err.Error(),
			))
		}
		if vaultStateConflict {
			tflog.Debug(ctx, fmt.Sprintf(
				"[OCI retry] PostDataV2 vault state conflict on attempt %d/%d, sleeping %s, endpoint: %s, error: %s",
				i+1, ociMaxRetries, sleep, endpoint, err.Error(),
			))
		}
		time.Sleep(sleep)
	}
	tflog.Warn(ctx, fmt.Sprintf(
		"[OCI retry] PostNoData all %d attempts exhausted, endpoint: %s, last error: %s",
		ociMaxRetries, endpoint, lastErr.Error(),
	))
	return "", lastErr
}

// ociPostDataV2WithRetry calls client.PostDataV2 and retries up to ociMaxRetries times
// when the error is an OCI throttling (TooManyRequests) response.
// Non-throttle errors are returned immediately without retrying.
// Successive waits follow an exponential backoff: 500 ms, 1 s, 2 s, 4 s.
// A warning is logged on every throttled attempt and after all retries are exhausted.
func ociPostDataV2WithRetry(
	ctx context.Context,
	client *common.Client,
	id string,
	endpoint string,
	data []byte,
) (string, error) {
	var lastErr error
	for i := 0; i < ociMaxRetries; i++ {
		resp, err := client.PostDataV2(ctx, id, endpoint, data)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		lastErr = err
		throttled := isOCIThrottleError(err)
		vaultStateConflict := isOCIVaultStateConflictError(err)
		if !throttled && !vaultStateConflict {
			return "", err
		}
		sleep := time.Duration(500*(1<<i)) * time.Millisecond
		if throttled {
			tflog.Warn(ctx, fmt.Sprintf(
				"[OCI retry] PostDataV2 throttled on attempt %d/%d, sleeping %s, endpoint: %s, error: %s",
				i+1, ociMaxRetries, sleep, endpoint, err.Error(),
			))
		}
		if vaultStateConflict {
			tflog.Debug(ctx, fmt.Sprintf(
				"[OCI retry] PostDataV2 vault state conflict on attempt %d/%d, sleeping %s, endpoint: %s, error: %s",
				i+1, ociMaxRetries, sleep, endpoint, err.Error(),
			))
		}
		time.Sleep(sleep)
	}
	tflog.Warn(ctx, fmt.Sprintf(
		"[OCI retry] PostDataV2 all %d attempts exhausted, endpoint: %s, last error: %s",
		ociMaxRetries, endpoint, lastErr.Error(),
	))
	return "", lastErr
}

// ociUpdateDataV2WithRetry calls client.UpdateDataV2 and retries up to ociMaxRetries times
// when the error is an OCI throttling (TooManyRequests) response.
// Non-throttle errors are returned immediately without retrying.
// Successive waits follow an exponential backoff: 500 ms, 1 s, 2 s, 4 s.
// A warning is logged on every throttled attempt and after all retries are exhausted.
func ociUpdateDataV2WithRetry(
	ctx context.Context,
	client *common.Client,
	resourceUUID string,
	endpoint string,
	data []byte,
) (string, error) {
	var lastErr error
	for i := 0; i < ociMaxRetries; i++ {
		resp, err := client.UpdateDataV2(ctx, resourceUUID, endpoint, data)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		lastErr = err
		throttled := isOCIThrottleError(err)
		vaultStateConflict := isOCIVaultStateConflictError(err)
		if !throttled && !vaultStateConflict {
			return "", err
		}
		sleep := time.Duration(500*(1<<i)) * time.Millisecond
		if throttled {
			tflog.Warn(ctx, fmt.Sprintf(
				"[OCI retry] UpdateDataV2 throttled on attempt %d/%d, sleeping %s, endpoint: %s, error: %s",
				i+1, ociMaxRetries, sleep, endpoint, err.Error(),
			))
		}
		if vaultStateConflict {
			tflog.Debug(ctx, fmt.Sprintf(
				"[OCI retry] PostDataV2 vault state conflict on attempt %d/%d, sleeping %s, endpoint: %s, error: %s",
				i+1, ociMaxRetries, sleep, endpoint, err.Error(),
			))
		}
		time.Sleep(sleep)
	}
	tflog.Warn(ctx, fmt.Sprintf(
		"[OCI retry] UpdateDataV2 all %d attempts exhausted, endpoint: %s, last error: %s",
		ociMaxRetries, endpoint, lastErr.Error(),
	))
	return "", lastErr
}
