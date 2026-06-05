package common

import "strings"

// notFoundError is the substring present in the error returned by the CM client
// (see client.go doRequest/doRequestBootstrap) when CipherTrust Manager responds
// with HTTP 404. The client formats failures as "status: %d, body: %s", so a 404
// always yields a string containing "status: 404".
const notFoundError = "status: 404"

// IsNotFoundError reports whether err represents an HTTP 404 (resource not found)
// response from CipherTrust Manager. Resource Read() implementations use it to
// detect out-of-band deletion and remove the resource from Terraform state.
func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), notFoundError)
}
