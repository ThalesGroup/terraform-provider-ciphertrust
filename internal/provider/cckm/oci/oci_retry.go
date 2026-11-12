package cckm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
)

// ociErrThrottled is the OCI error code for transient rate-throttle responses (HTTP 429).
// "TooManyRequests" is injected into the error body by OCI itself; CCKM passes it through
// unchanged. Checking only this string (and not the HTTP status code) makes the predicate
// robust against any future CCKM formatting changes to how the status code is reported.
// ociVaultStateConflictError can occur after an operation like restoring a key from backup
// The vault state is in a state of "restoring" for a short period and some operations can fail as a result.
// ociEmptyServerError is the error text produced by the common client for an HTTP 500
// response with an empty body (format is "status: 500, body: "). CCKM can intermittently
// return this when a background task fails; it is retried over a short, bounded window.
const (
	ociErrThrottled            = "TooManyRequests"
	ociVaultStateConflictError = "Vault must be in one of the following states"
	ociEmptyServerError        = "status: 500, body:"
	ociMaxRetries              = 10
	ociVaultConflictSleep      = 10 * time.Second
	ociServerErrorMaxRetries   = 6
	ociServerErrorSleep        = 5 * time.Second
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

// isOCIEmptyServerError returns true only for an HTTP 500 whose response body is empty.
// A 500 that carries any body text is a real error and is not retried.
func isOCIEmptyServerError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	idx := strings.Index(msg, ociEmptyServerError)
	if idx < 0 {
		return false
	}
	return strings.TrimSpace(msg[idx+len(ociEmptyServerError):]) == ""
}

// ociGetByIdWithRetry calls client.GetById and retries only on an HTTP 500 with an empty
// body, up to ociServerErrorMaxRetries times with ociServerErrorSleep between attempts.
// All other errors are returned immediately. Every retry is logged.
func ociGetByIdWithRetry(
	ctx context.Context,
	client *common.Client,
	id string,
	resourceID string,
	endpoint string,
) (string, error) {
	var lastErr error
	for i := 0; i < ociServerErrorMaxRetries; i++ {
		resp, err := client.GetById(ctx, id, resourceID, endpoint)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !isOCIEmptyServerError(err) {
			return "", err
		}
		client.Log.Warn(fmt.Sprintf(
			"[OCI retry] GetById empty-body 500 on attempt %d/%d, sleeping %s, endpoint: %s/%s",
			i+1, ociServerErrorMaxRetries, ociServerErrorSleep, endpoint, resourceID,
		))
		time.Sleep(ociServerErrorSleep)
	}
	client.Log.Warn(fmt.Sprintf(
		"[OCI retry] GetById all %d attempts exhausted, endpoint: %s/%s, last error: %s",
		ociServerErrorMaxRetries, endpoint, resourceID, lastErr.Error(),
	))
	return "", lastErr
}

// ociRetrySleep decides whether err is retryable for the POST/UPDATE helpers and returns
// the sleep to use. serverErrCount tracks empty-body 500 retries so they use their own
// bounded budget. ok is false when the error must be returned to the caller.
func ociRetrySleep(client *common.Client, op string, endpoint string, attempt int, serverErrCount *int, err error) (time.Duration, bool) {
	throttled := isOCIThrottleError(err)
	vaultStateConflict := isOCIVaultStateConflictError(err)
	emptyServerErr := isOCIEmptyServerError(err)
	if !throttled && !vaultStateConflict && !emptyServerErr {
		return 0, false
	}
	var sleep time.Duration
	switch {
	case emptyServerErr:
		if *serverErrCount >= ociServerErrorMaxRetries {
			return 0, false
		}
		*serverErrCount++
		sleep = ociServerErrorSleep
		client.Log.Warn(fmt.Sprintf(
			"[OCI retry] %s empty-body 500 on attempt %d/%d, sleeping %s, endpoint: %s",
			op, *serverErrCount, ociServerErrorMaxRetries, sleep, endpoint,
		))
	case vaultStateConflict:
		sleep = ociVaultConflictSleep
		client.Log.Debug(fmt.Sprintf(
			"[OCI retry] %s vault state conflict on attempt %d/%d, sleeping %s, endpoint: %s, error: %s",
			op, attempt+1, ociMaxRetries, sleep, endpoint, err.Error(),
		))
	default:
		sleep = time.Duration(500*(1<<attempt)) * time.Millisecond
		client.Log.Warn(fmt.Sprintf(
			"[OCI retry] %s throttled on attempt %d/%d, sleeping %s, endpoint: %s, error: %s",
			op, attempt+1, ociMaxRetries, sleep, endpoint, err.Error(),
		))
	}
	return sleep, true
}

// ociPostNoDataWithRetry calls client.PostNoData and retries up to ociMaxRetries times
// when the error is an OCI throttling (TooManyRequests) response or a vault state conflict.
// An HTTP 500 with an empty body is retried up to ociServerErrorMaxRetries times.
// Other errors are returned immediately without retrying.
// Throttle waits follow an exponential backoff: 500 ms, 1 s, 2 s, 4 s.
// A warning is logged on every retry and after all retries are exhausted.
func ociPostNoDataWithRetry(
	ctx context.Context,
	client *common.Client,
	id string,
	endpoint string,
) (string, error) {
	var lastErr error
	serverErrCount := 0
	for i := 0; i < ociMaxRetries; i++ {
		resp, err := client.PostNoData(ctx, id, endpoint)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		sleep, ok := ociRetrySleep(client, "PostNoData", endpoint, i, &serverErrCount, err)
		if !ok {
			return "", err
		}
		time.Sleep(sleep)
	}
	client.Log.Warn(fmt.Sprintf(
		"[OCI retry] PostNoData all %d attempts exhausted, endpoint: %s, last error: %s",
		ociMaxRetries, endpoint, lastErr.Error(),
	))
	return "", lastErr
}

// ociPostDataV2WithRetry calls client.PostDataV2 and retries up to ociMaxRetries times
// when the error is an OCI throttling (TooManyRequests) response or a vault state conflict.
// An HTTP 500 with an empty body is retried up to ociServerErrorMaxRetries times.
// Other errors are returned immediately without retrying.
// Throttle waits follow an exponential backoff: 500 ms, 1 s, 2 s, 4 s.
// A warning is logged on every retry and after all retries are exhausted.
func ociPostDataV2WithRetry(
	ctx context.Context,
	client *common.Client,
	id string,
	endpoint string,
	data []byte,
) (string, error) {
	var lastErr error
	serverErrCount := 0
	for i := 0; i < ociMaxRetries; i++ {
		resp, err := client.PostDataV2(ctx, id, endpoint, data)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		sleep, ok := ociRetrySleep(client, "PostDataV2", endpoint, i, &serverErrCount, err)
		if !ok {
			return "", err
		}
		time.Sleep(sleep)
	}
	client.Log.Warn(fmt.Sprintf(
		"[OCI retry] PostDataV2 all %d attempts exhausted, endpoint: %s, last error: %s",
		ociMaxRetries, endpoint, lastErr.Error(),
	))
	return "", lastErr
}

// ociUpdateDataV2WithRetry calls client.UpdateDataV2 and retries up to ociMaxRetries times
// when the error is an OCI throttling (TooManyRequests) response or a vault state conflict.
// An HTTP 500 with an empty body is retried up to ociServerErrorMaxRetries times.
// Other errors are returned immediately without retrying.
// Throttle waits follow an exponential backoff: 500 ms, 1 s, 2 s, 4 s.
// A warning is logged on every retry and after all retries are exhausted.
func ociUpdateDataV2WithRetry(
	ctx context.Context,
	client *common.Client,
	resourceUUID string,
	endpoint string,
	data []byte,
) (string, error) {
	var lastErr error
	serverErrCount := 0
	for i := 0; i < ociMaxRetries; i++ {
		resp, err := client.UpdateDataV2(ctx, resourceUUID, endpoint, data)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		sleep, ok := ociRetrySleep(client, "UpdateDataV2", endpoint, i, &serverErrCount, err)
		if !ok {
			return "", err
		}
		time.Sleep(sleep)
	}
	client.Log.Warn(fmt.Sprintf(
		"[OCI retry] UpdateDataV2 all %d attempts exhausted, endpoint: %s, last error: %s",
		ociMaxRetries, endpoint, lastErr.Error(),
	))
	return "", lastErr
}
