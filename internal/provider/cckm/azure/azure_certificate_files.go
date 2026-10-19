package cckm

import (
	"encoding/base64"
	"os"
	"strings"
)

// azureFileOrContent returns the contents of the file at value if it exists. Otherwise value is
// returned unchanged and is assumed to be the content itself.
func azureFileOrContent(value string) (string, error) {
	data, isFile, err := azureReadFileIfExists(value)
	if err != nil {
		return "", err
	}
	if isFile {
		return string(data), nil
	}
	return value, nil
}

// azureCertificateContent resolves the certificate value. If it is a file, PEM text and already
// base64 encoded text are returned as is and anything else is treated as a binary PFX and base64
// encoded. If it is not a file it is returned unchanged.
func azureCertificateContent(value string) (string, error) {
	data, isFile, err := azureReadFileIfExists(value)
	if err != nil {
		return "", err
	}
	if !isFile {
		return value, nil
	}
	text := strings.TrimSpace(string(data))
	if strings.Contains(text, "-----BEGIN") || azureIsBase64Text(text) {
		return text, nil
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func azureReadFileIfExists(value string) ([]byte, bool, error) {
	path := strings.TrimSpace(value)
	if path == "" {
		return nil, false, nil
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil, false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func azureIsBase64Text(text string) bool {
	if text == "" {
		return false
	}
	for _, c := range text {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '=', c == '\n', c == '\r', c == ' ', c == '\t':
		default:
			return false
		}
	}
	return true
}
