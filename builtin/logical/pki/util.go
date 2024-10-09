// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"

	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	defaultRef = "default"

	// Constants for If-Modified-Since operation
	headerIfModifiedSince = "If-Modified-Since"
	headerLastModified    = "Last-Modified"
)

var (
	nameMatcher          = regexp.MustCompile("^" + framework.GenericNameRegex(issuerRefParam) + "$")
	errIssuerNameInUse   = errutil.UserError{Err: "issuer name already in use"}
	errIssuerNameIsEmpty = errutil.UserError{Err: "expected non-empty issuer name"}
	errKeyNameInUse      = errutil.UserError{Err: "key name already in use"}
)

func serialFromCert(cert *x509.Certificate) string {
	return serialFromBigInt(cert.SerialNumber)
}

func serialFromBigInt(serial *big.Int) string {
	return strings.TrimSpace(certutil.GetHexFormatted(serial.Bytes(), ":"))
}

func normalizeSerialFromBigInt(serial *big.Int) string {
	return strings.TrimSpace(certutil.GetHexFormatted(serial.Bytes(), "-"))
}

func normalizeSerial(serial string) string {
	return strings.ReplaceAll(strings.ToLower(serial), ":", "-")
}

func denormalizeSerial(serial string) string {
	return strings.ReplaceAll(strings.ToLower(serial), "-", ":")
}

func existingKeyRequested(input *inputBundle) bool {
	return existingKeyRequestedFromFieldData(input.apiData)
}

func existingKeyRequestedFromFieldData(data *framework.FieldData) bool {
	exportedStr, ok := data.GetOk("exported")
	if !ok {
		return false
	}
	return exportedStr.(string) == "existing"
}

func getKeyRefWithErr(data *framework.FieldData) (string, error) {
	keyRef := getKeyRef(data)

	if len(keyRef) == 0 {
		return "", errutil.UserError{Err: "missing argument key_ref for existing type"}
	}

	return keyRef, nil
}

func getIssuerName(sc *storageContext, data *framework.FieldData) (string, error) {
	issuerName := ""
	issuerNameIface, ok := data.GetOk("issuer_name")
	if ok {
		issuerName = strings.TrimSpace(issuerNameIface.(string))
		if len(issuerName) == 0 {
			return issuerName, errIssuerNameIsEmpty
		}
		if strings.ToLower(issuerName) == defaultRef {
			return issuerName, errutil.UserError{Err: "reserved keyword 'default' can not be used as issuer name"}
		}
		if !nameMatcher.MatchString(issuerName) {
			return issuerName, errutil.UserError{Err: "issuer name contained invalid characters"}
		}
		issuerId, err := sc.resolveIssuerReference(issuerName)
		if err == nil {
			return issuerName, errIssuerNameInUse
		}

		if err != nil && issuerId != IssuerRefNotFound {
			return issuerName, errutil.InternalError{Err: err.Error()}
		}
	}
	return issuerName, nil
}

func getKeyName(sc *storageContext, data *framework.FieldData) (string, error) {
	keyName := ""
	keyNameIface, ok := data.GetOk(keyNameParam)
	if ok {
		keyName = strings.TrimSpace(keyNameIface.(string))

		if strings.ToLower(keyName) == defaultRef {
			return "", errutil.UserError{Err: "reserved keyword 'default' can not be used as key name"}
		}

		if !nameMatcher.MatchString(keyName) {
			return "", errutil.UserError{Err: "key name contained invalid characters"}
		}
		keyId, err := sc.resolveKeyReference(keyName)
		if err == nil {
			return "", errKeyNameInUse
		}

		if err != nil && keyId != KeyRefNotFound {
			return "", errutil.InternalError{Err: err.Error()}
		}
	}
	return keyName, nil
}

func getIssuerRef(data *framework.FieldData) string {
	return extractRef(data, issuerRefParam)
}

func getKeyRef(data *framework.FieldData) string {
	return extractRef(data, keyRefParam)
}

func extractRef(data *framework.FieldData, paramName string) string {
	value := strings.TrimSpace(data.Get(paramName).(string))
	if strings.EqualFold(value, defaultRef) {
		return defaultRef
	}
	return value
}

func isStringArrayDifferent(a, b []string) bool {
	if len(a) != len(b) {
		return true
	}

	for i, v := range a {
		if v != b[i] {
			return true
		}
	}

	return false
}

func hasHeader(header string, req *logical.Request) bool {
	var hasHeader bool
	headerValue := req.Headers[header]
	if len(headerValue) > 0 {
		hasHeader = true
	}

	return hasHeader
}

func parseIfNotModifiedSince(req *logical.Request) (time.Time, error) {
	var headerTimeValue time.Time
	headerValue := req.Headers[headerIfModifiedSince]

	headerTimeValue, err := time.Parse(time.RFC1123, headerValue[0])
	if err != nil {
		return headerTimeValue, fmt.Errorf("failed to parse given value for '%s' header: %w", headerIfModifiedSince, err)
	}

	return headerTimeValue, nil
}

type ifModifiedReqType int

const (
	ifModifiedUnknown  ifModifiedReqType = iota
	ifModifiedCA                         = iota
	ifModifiedCRL                        = iota
	ifModifiedDeltaCRL                   = iota
)

type IfModifiedSinceHelper struct {
	req       *logical.Request
	reqType   ifModifiedReqType
	issuerRef issuerID
}

func sendNotModifiedResponseIfNecessary(helper *IfModifiedSinceHelper, sc *storageContext, resp *logical.Response) (bool, error) {
	responseHeaders := map[string][]string{}
	if !hasHeader(headerIfModifiedSince, helper.req) {
		return false, nil
	}

	before, err := sc.isIfModifiedSinceBeforeLastModified(helper, responseHeaders)
	if err != nil {
		return false, err
	}

	if !before {
		return false, nil
	}

	// Fill response
	resp.Data = map[string]interface{}{
		logical.HTTPContentType: "",
		logical.HTTPStatusCode:  304,
	}
	resp.Headers = responseHeaders

	return true, nil
}

func (sc *storageContext) isIfModifiedSinceBeforeLastModified(helper *IfModifiedSinceHelper, responseHeaders map[string][]string) (bool, error) {
	// False return --> we were last modified _before_ the requester's
	// time --> keep using the cached copy and return 304.
	var err error
	var lastModified time.Time
	ifModifiedSince, err := parseIfNotModifiedSince(helper.req)
	if err != nil {
		return false, err
	}

	switch helper.reqType {
	case ifModifiedCRL, ifModifiedDeltaCRL:
		if sc.Backend.crlBuilder.invalidate.Load() {
			// When we see the CRL is invalidated, respond with false
			// regardless of what the local CRL state says. We've likely
			// renamed some issuers or are about to rebuild a new CRL....
			//
			// We do this earlier, ahead of config load, as it saves us a
			// potential error condition.
			return false, nil
		}

		crlConfig, err := sc.getLocalCRLConfig()
		if err != nil {
			return false, err
		}

		lastModified = crlConfig.LastModified
		if helper.reqType == ifModifiedDeltaCRL {
			lastModified = crlConfig.DeltaLastModified
		}
	case ifModifiedCA:
		issuerId, err := sc.resolveIssuerReference(string(helper.issuerRef))
		if err != nil {
			return false, err
		}

		issuer, err := sc.fetchIssuerById(issuerId)
		if err != nil {
			return false, err
		}

		lastModified = issuer.LastModified
	default:
		return false, fmt.Errorf("unknown if-modified-since request type: %v", helper.reqType)
	}

	if !lastModified.IsZero() && lastModified.Before(ifModifiedSince) {
		responseHeaders[headerLastModified] = []string{lastModified.Format(http.TimeFormat)}
		return true, nil
	}

	return false, nil
}

func addWarnings(resp *logical.Response, warnings []string) *logical.Response {
	for _, warning := range warnings {
		resp.AddWarning(warning)
	}
	return resp
}
