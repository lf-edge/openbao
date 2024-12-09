// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/crypto/ssh"
)

const (
	issuerRefParam = "issuer_ref"
)

var (
	nameMatcher          = regexp.MustCompile("^" + framework.GenericNameRegex(issuerRefParam) + "$")
	errIssuerNameInUse   = errutil.UserError{Err: "issuer name already in use"}
	errIssuerNameIsEmpty = errutil.UserError{Err: "expected non-empty issuer name"}
)

// Creates a new RSA key pair with the given key length. The private key will be
// of pem format and the public key will be of OpenSSH format.
func generateRSAKeys(keyBits int) (publicKeyRsa string, privateKeyRsa string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return "", "", fmt.Errorf("error generating RSA key-pair: %w", err)
	}

	privateKeyRsa = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}))

	sshPublicKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return "", "", fmt.Errorf("error generating RSA key-pair: %w", err)
	}
	publicKeyRsa = "ssh-rsa " + base64.StdEncoding.EncodeToString(sshPublicKey.Marshal())
	return
}

// Takes an IP address and role name and checks if the IP is part
// of CIDR blocks belonging to the role.
func roleContainsIP(ctx context.Context, s logical.Storage, roleName string, ip string) (bool, error) {
	if roleName == "" {
		return false, errors.New("missing role name")
	}

	if ip == "" {
		return false, errors.New("missing ip")
	}

	roleEntry, err := s.Get(ctx, fmt.Sprintf("roles/%s", roleName))
	if err != nil {
		return false, fmt.Errorf("error retrieving role %w", err)
	}
	if roleEntry == nil {
		return false, fmt.Errorf("role %q not found", roleName)
	}

	var role sshRole
	if err := roleEntry.DecodeJSON(&role); err != nil {
		return false, fmt.Errorf("error decoding role %q", roleName)
	}

	if matched, err := cidrListContainsIP(ip, role.CIDRList); err != nil {
		return false, err
	} else {
		return matched, nil
	}
}

// Returns true if the IP supplied by the user is part of the comma
// separated CIDR blocks
func cidrListContainsIP(ip, cidrList string) (bool, error) {
	if len(cidrList) == 0 {
		return false, errors.New("IP does not belong to role")
	}
	for _, item := range strings.Split(cidrList, ",") {
		_, cidrIPNet, err := net.ParseCIDR(item)
		if err != nil {
			return false, fmt.Errorf("invalid CIDR entry %q", item)
		}
		if cidrIPNet.Contains(net.ParseIP(ip)) {
			return true, nil
		}
	}
	return false, nil
}

func parsePublicSSHKey(key string) (ssh.PublicKey, error) {
	keyParts := strings.Split(key, " ")
	if len(keyParts) > 1 {
		// Someone has sent the 'full' public key rather than just the base64 encoded part that the ssh library wants
		key = keyParts[1]
	}

	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePublicKey([]byte(decodedKey))
}

func convertMapToStringValue(initial map[string]interface{}) map[string]string {
	result := map[string]string{}
	for key, value := range initial {
		result[key] = fmt.Sprintf("%v", value)
	}
	return result
}

func convertMapToIntSlice(initial map[string]interface{}) (map[string][]int, error) {
	var err error
	result := map[string][]int{}

	for key, value := range initial {
		result[key], err = parseutil.SafeParseIntSlice(value, 0 /* no upper bound on number of keys lengths per key type */)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Serve a template processor for custom format inputs
func substQuery(tpl string, data map[string]string) string {
	for k, v := range data {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}

	return tpl
}

// keys parses the input parameters and returns the public and private keys
// by either generating them or using the provided ones.
// NOTE: The code is exactly the same as the one in `pathConfigCAUpdate`.
func (b *backend) keys(data *framework.FieldData) (string, string, error) {
	var err error
	publicKey := data.Get("public_key").(string)
	privateKey := data.Get("private_key").(string)

	var generateSigningKey bool

	generateSigningKeyRaw, ok := data.GetOk("generate_signing_key")
	switch {
	// explicitly set true
	case ok && generateSigningKeyRaw.(bool):
		if publicKey != "" || privateKey != "" {
			return "", "", errors.New("public_key and private_key must not be set when generate_signing_key is set to true")
		}

		generateSigningKey = true

	// explicitly set to false, or not set and we have both a public and private key
	case ok, publicKey != "" && privateKey != "":
		if publicKey == "" {
			return "", "", errors.New("missing public_key")
		}

		if privateKey == "" {
			return "", "", errors.New("missing private_key")
		}

		_, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return "", "", fmt.Errorf("Unable to parse private_key as an SSH private key: %v", err)
		}

		_, err = parsePublicSSHKey(publicKey)
		if err != nil {
			return "", "", fmt.Errorf("Unable to parse public_key as an SSH public key: %w", err)
		}

	// not set and no public/private key provided so generate
	case publicKey == "" && privateKey == "":
		generateSigningKey = true

	// not set, but one or the other supplied
	default:
		return "", "", errors.New("only one of public_key and private_key set; both must be set to use, or both must be blank to auto-generate")
	}

	if generateSigningKey {
		keyType := data.Get("key_type").(string)
		keyBits := data.Get("key_bits").(int)

		publicKey, privateKey, err = generateSSHKeyPair(b.Backend.GetRandomReader(), keyType, keyBits)
		if err != nil {
			return "", "", errutil.InternalError{Err: err.Error()}
		}
	}

	if publicKey == "" || privateKey == "" {
		return "", "", errutil.InternalError{Err: "failed to generate or parse the keys"}
	}

	return publicKey, privateKey, nil
}

func getIssuerRef(data *framework.FieldData) string {
	return extractRef(data, issuerRefParam)
}

func getDefaultRef(data *framework.FieldData) string {
	return extractRef(data, defaultRef)
}

func extractRef(data *framework.FieldData, paramName string) string {
	value := strings.TrimSpace(data.Get(paramName).(string))
	if strings.EqualFold(value, defaultRef) {
		return defaultRef
	}
	return value
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

// handleStorageContextErr is a small helper function to automatically return
// internal failed operations as errors, 500 status codes, and users errors
// as responses, with 400 status code.
func handleStorageContextErr(err error) (*logical.Response, error) {
	switch err.(type) {
	case errutil.UserError:
		return logical.ErrorResponse(err.Error()), nil
	case errutil.InternalError:
		return nil, err
	default:
		return nil, err
	}
}
