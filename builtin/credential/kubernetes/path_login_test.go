// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kubeauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	matchLabelsKeyValue = `{
	"matchLabels": {
		"key": "value"
	}
}`
	mismatchLabelsKeyValue = `{
	"matchLabels": {
		"foo": "bar"
	}
}`
)

var (
	testNamespace                    = "default"
	testName                         = "vault-auth"
	testUID                          = "d77f89bc-9055-11e7-a068-0800276d99bf"
	testMockTokenReviewFactory       = mockTokenReviewFactory(testName, testNamespace, testUID)
	testMockNamespaceValidateFactory = mockNamespaceValidateFactory(
		map[string]string{"key": "value", "other": "label"})

	testGlobbedNamespace = "def*"
	testGlobbedName      = "vault-*"

	// Projected ServiceAccount tokens have name "default", and require a
	// different mock token reviewer
	testProjectedName                   = "default"
	testProjectedUID                    = "77c81ad7-1bea-4d94-9ca5-f5d7f3632331"
	testProjectedMockTokenReviewFactory = mockTokenReviewFactory(testProjectedName, testNamespace, testProjectedUID)

	testDefaultPEMs      []string
	ecdsaPrivateKey      *ecdsa.PrivateKey
	ecdsaOtherPrivateKey *ecdsa.PrivateKey

	jwtES256Header = `{
  "alg": "ES256",
  "typ": "JWT"
}`
	jwtGoodDataPayload = `{
  "iss": "kubernetes/serviceaccount",
  "kubernetes.io/serviceaccount/namespace": "default",
  "kubernetes.io/serviceaccount/secret.name": "vault-auth-token-t5pcn",
  "kubernetes.io/serviceaccount/service-account.name": "vault-auth",
  "kubernetes.io/serviceaccount/service-account.uid": "d77f89bc-9055-11e7-a068-0800276d99bf",
  "sub": "system:serviceaccount:default:vault-auth"
}`
	jwtInvalidPayload = `{
  "iss": "kubernetes/serviceaccount",
  "kubernetes.io/serviceaccount/namespace": "default",
  "kubernetes.io/serviceaccount/secret.name": "vault-invalid-token-gvqpt",
  "kubernetes.io/serviceaccount/service-account.name": "vault-auth",
  "kubernetes.io/serviceaccount/service-account.uid": "044fd4f1-974d-11e7-9a15-0800276d99bf",
  "sub": "system:serviceaccount:default:vault-auth"
}`
	jwtBadServiceAccountPayload = `{
  "iss": "kubernetes/serviceaccount",
  "kubernetes.io/serviceaccount/namespace": "default",
  "kubernetes.io/serviceaccount/secret.name": "vault-invalid-token-gvqpt",
  "kubernetes.io/serviceaccount/service-account.name": "vault-invalid",
  "kubernetes.io/serviceaccount/service-account.uid": "044fd4f1-974d-11e7-9a15-0800276d99bf",
  "sub": "system:serviceaccount:default:vault-invalid"
}`
	jwtProjectedDataPayload = `{
  "aud": [
    "kubernetes.default.svc"
  ],
  "exp": 1920082797,
  "iat": 1604082797,
  "iss": "kubernetes/serviceaccount",
  "kubernetes.io": {
    "namespace": "default",
    "pod": {
      "name": "vault",
      "uid": "086c2f61-dea2-47bb-b5ca-63e63c5c9885"
    },
    "serviceaccount": {
      "name": "default",
      "uid": "77c81ad7-1bea-4d94-9ca5-f5d7f3632331"
    }
  },
  "nbf": 1604082797,
  "sub": "system:serviceaccount:default:default"
}`

	jwtProjectedDataExpiredPayload = `{
  "aud": [
    "kubernetes.default.svc"
  ],
  "exp": 1604083886,
  "iat": 1604083286,
  "iss": "kubernetes/serviceaccount",
  "kubernetes.io": {
    "namespace": "default",
    "pod": {
      "name": "vault",
      "uid": "34be4d5f-66d3-4a29-beea-ce23e51f9fb8"
    },
    "serviceaccount": {
      "name": "default",
      "uid": "77c81ad7-1bea-4d94-9ca5-f5d7f3632331"
    }
  },
  "nbf": 1604083286,
  "sub": "system:serviceaccount:default:default"
}`

	// computed below by init()
	jwtGoodDataToken          = ""
	jwtBadServiceAccountToken = ""
	jwtBadSigningKeyToken     = ""
	jwtProjectedDataExpired   = ""
	jwtProjectedData          = ""
)

func init() {
	var err error
	ecdsaPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	ecdsaOtherPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	var blockBytes []byte
	blockBytes, err = x509.MarshalPKIXPublicKey(ecdsaPrivateKey.Public())
	ecdsaPublicKeyText := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: blockBytes,
	})
	testDefaultPEMs = []string{string(ecdsaPublicKeyText)}

	jwtGoodDataToken = jwtSign(jwtES256Header, patchIat(jwtGoodDataPayload), ecdsaPrivateKey)
	jwtBadServiceAccountToken = jwtSign(jwtES256Header, patchIat(jwtBadServiceAccountPayload), ecdsaPrivateKey)

	jwtProjectedData = jwtSign(jwtES256Header, patchExp(patchIat(jwtProjectedDataPayload)), ecdsaPrivateKey)
	// don't patch Issued At
	jwtProjectedDataExpired = jwtSign(jwtES256Header, jwtProjectedDataExpiredPayload, ecdsaPrivateKey)

	// sign with an unknown key
	jwtBadSigningKeyToken = jwtSign(jwtES256Header, patchIat(jwtInvalidPayload), ecdsaOtherPrivateKey)
}

// patches in the Issued At time to be now
func patchIat(input string) string {
	m := map[string]interface{}{}
	err := json.Unmarshal([]byte(input), &m)
	if err != nil {
		panic(err)
	}
	m["iat"] = time.Now().Unix()
	out, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(out)
}

// patches in the Expires time to be 10 years from now
func patchExp(input string) string {
	m := map[string]interface{}{}
	err := json.Unmarshal([]byte(input), &m)
	if err != nil {
		panic(err)
	}
	m["exp"] = time.Now().AddDate(10, 0, 0).Unix()
	out, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(out)
}

// creates a signed JWT token
func jwtSign(header string, payload string, privateKey *ecdsa.PrivateKey) string {
	header64 := strings.ReplaceAll(base64.URLEncoding.EncodeToString([]byte(header)), "=", "")
	payload64 := strings.ReplaceAll(base64.URLEncoding.EncodeToString([]byte(payload)), "=", "")
	toSign := header64 + "." + payload64

	sha := crypto.SHA256.New()
	sha.Write([]byte(toSign))
	digest := sha.Sum([]byte{})
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		panic(err)
	}
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rBytes = append(rBytes, sBytes...)
	sig64 := strings.ReplaceAll(base64.URLEncoding.EncodeToString(rBytes), "=", "")
	return toSign + "." + sig64
}

type testBackendConfig struct {
	pems                []string
	saName              string
	saNamespace         string
	saNamespaceSelector string
	aliasNameSource     string
}

func defaultTestBackendConfig() *testBackendConfig {
	return &testBackendConfig{
		pems:                testDefaultPEMs,
		saName:              testName,
		saNamespace:         testNamespace,
		saNamespaceSelector: "",
		aliasNameSource:     aliasNameSourceDefault,
	}
}

func setupBackend(t *testing.T, config *testBackendConfig) (logical.Backend, logical.Storage) {
	b, storage := getBackend(t)

	// test no certificate
	data := map[string]interface{}{
		"pem_keys":           config.pems,
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	data = map[string]interface{}{
		"bound_service_account_names":              config.saName,
		"bound_service_account_namespaces":         config.saNamespace,
		"bound_service_account_namespace_selector": config.saNamespaceSelector,
		"policies":          "test",
		"period":            "3s",
		"ttl":               "1s",
		"num_uses":          12,
		"max_ttl":           "5s",
		"alias_name_source": config.aliasNameSource,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	b.(*kubeAuthBackend).reviewFactory = testMockTokenReviewFactory
	b.(*kubeAuthBackend).namespaceValidatorFactory = testMockNamespaceValidateFactory
	return b, storage
}

func TestLogin(t *testing.T) {
	b, storage := setupBackend(t, defaultTestBackendConfig())

	// Test bad inputs
	data := map[string]interface{}{
		"jwt": jwtGoodDataToken,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "missing role" {
		t.Fatalf("unexpected error: %s", resp.Error())
	}

	data = map[string]interface{}{
		"role": "plugin-test",
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "missing jwt" {
		t.Fatalf("unexpected error: %s", resp.Error())
	}

	// test bad role name
	data = map[string]interface{}{
		"role": "plugin-test-bad",
		"jwt":  jwtGoodDataToken,
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != `invalid role name "plugin-test-bad"` {
		t.Fatalf("unexpected error: %s", resp.Error())
	}

	// test bad jwt service account
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtBadServiceAccountToken,
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "service account name not authorized" {
		t.Fatalf("unexpected error: %s", err)
	}
	requireErrorCode(t, err, http.StatusForbidden)

	// test bad jwt key
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtBadSigningKeyToken,
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatalf("Expected error")
	} else if !errors.Is(err, logical.ErrPermissionDenied) {
		t.Fatalf("unexpected error: %s", err)
	}

	// test successful login
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test successful login for globbed name
	config := defaultTestBackendConfig()
	config.saName = testGlobbedName
	b, storage = setupBackend(t, config)

	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test successful login for globbed namespace
	config = defaultTestBackendConfig()
	config.saNamespace = testGlobbedNamespace
	b, storage = setupBackend(t, config)

	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func TestLogin_ContextError(t *testing.T) {
	b, storage := setupBackend(t, defaultTestBackendConfig())

	data := map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := b.HandleRequest(ctx, req)
	if err != context.Canceled {
		t.Fatalf("expected context canceled error, got: %v", err)
	}
}

func TestLogin_ECDSA_PEM(t *testing.T) {
	config := defaultTestBackendConfig()
	b, storage := setupBackend(t, config)

	// test no certificate
	data := map[string]interface{}{
		"pem_keys":           testDefaultPEMs,
		"kubernetes_host":    "host",
		"kubernetes_ca_cert": testCACert,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test successful login
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func TestLogin_NoPEMs(t *testing.T) {
	config := defaultTestBackendConfig()
	b, storage := setupBackend(t, config)

	// test bad jwt service account
	data := map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtBadServiceAccountToken,
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "service account name not authorized" {
		t.Fatalf("unexpected error: %s", err)
	}
	requireErrorCode(t, err, http.StatusForbidden)

	// test successful login
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func TestLoginSvcAcctAndNamespaceSplats(t *testing.T) {
	config := defaultTestBackendConfig()
	config.saName = "*"
	config.saNamespace = "*"
	b, storage := setupBackend(t, config)

	// Test bad inputs
	data := map[string]interface{}{
		"jwt": jwtGoodDataToken,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "missing role" {
		t.Fatalf("unexpected error: %s", resp.Error())
	}

	data = map[string]interface{}{
		"role": "plugin-test",
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != "missing jwt" {
		t.Fatalf("unexpected error: %s", resp.Error())
	}

	// test bad role name
	data = map[string]interface{}{
		"role": "plugin-test-bad",
		"jwt":  jwtGoodDataToken,
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != `invalid role name "plugin-test-bad"` {
		t.Fatalf("unexpected error: %s", resp.Error())
	}

	// test bad jwt service account
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtBadServiceAccountToken,
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(logical.ErrPermissionDenied, err) {
		t.Fatalf("unexpected error: %s", err)
	}

	// test bad jwt key
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtBadSigningKeyToken,
	}
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatalf("Expected error")
	} else if !errors.Is(logical.ErrPermissionDenied, err) {
		t.Fatalf("unexpected error: %s", err)
	}

	// test successful login
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test successful login for globbed name
	config = defaultTestBackendConfig()
	config.saName = testGlobbedName
	b, storage = setupBackend(t, config)

	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test successful login for globbed namespace
	config = defaultTestBackendConfig()
	config.saNamespace = testGlobbedNamespace
	b, storage = setupBackend(t, config)

	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func TestLoginSvcAcctNamespaceSelector(t *testing.T) {
	testCases := map[string]struct {
		saNamespaceSelector string
		errExpected         bool
		expectedErrCode     int
	}{
		"matchNamespaceSelector": {
			saNamespaceSelector: matchLabelsKeyValue,
		},
		"mismatchNamespaceSelector": {
			saNamespaceSelector: mismatchLabelsKeyValue,
			errExpected:         true,
			expectedErrCode:     http.StatusForbidden,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			config := defaultTestBackendConfig()
			config.saName = "*"
			config.saNamespace = "non-default"
			config.saNamespaceSelector = tc.saNamespaceSelector
			b, storage := setupBackend(t, config)

			data := map[string]interface{}{
				"role": "plugin-test",
				"jwt":  jwtGoodDataToken,
			}

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "login",
				Storage:   storage,
				Data:      data,
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.1",
				},
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if tc.errExpected {
				var actual error
				if err != nil {
					actual = err
				} else if resp != nil && resp.IsError() {
					actual = resp.Error()
				} else {
					t.Fatalf("expected error")
				}

				if tc.expectedErrCode != 0 {
					requireErrorCode(t, actual, tc.expectedErrCode)
				}
			} else {
				if err != nil || (resp != nil && resp.IsError()) {
					t.Fatalf("err:%s resp:%#v\n", err, resp)
				}
			}
		})
	}
}

func TestAliasLookAhead(t *testing.T) {
	testCases := map[string]struct {
		role              string
		jwt               string
		config            *testBackendConfig
		expectedAliasName string
		wantErr           error
		wantErrCode       int
	}{
		"default": {
			role:              "plugin-test",
			jwt:               jwtGoodDataToken,
			config:            defaultTestBackendConfig(),
			expectedAliasName: testUID,
		},
		"no_role": {
			jwt:     jwtGoodDataToken,
			config:  defaultTestBackendConfig(),
			wantErr: errors.New("missing role"),
		},
		"no_jwt": {
			role:    "plugin-test",
			config:  defaultTestBackendConfig(),
			wantErr: errors.New("missing jwt"),
		},
		"invalid_jwt": {
			role:        "plugin-test",
			config:      defaultTestBackendConfig(),
			jwt:         jwtBadServiceAccountToken,
			wantErr:     errors.New("service account name not authorized"),
			wantErrCode: http.StatusForbidden,
		},
		"wrong_namespace": {
			role: "plugin-test",
			jwt:  jwtGoodDataToken,
			config: func() *testBackendConfig {
				config := defaultTestBackendConfig()
				config.saNamespace = "wrong-namespace"
				return config
			}(),
			wantErr:     errors.New("namespace not authorized"),
			wantErrCode: http.StatusForbidden,
		},
		"serviceaccount_uid": {
			role: "plugin-test",
			jwt:  jwtGoodDataToken,
			config: &testBackendConfig{
				pems:            testDefaultPEMs,
				saName:          testName,
				saNamespace:     testNamespace,
				aliasNameSource: aliasNameSourceSAUid,
			},
			expectedAliasName: testUID,
		},
		"serviceaccount_name": {
			role: "plugin-test",
			jwt:  jwtGoodDataToken,
			config: &testBackendConfig{
				pems:            testDefaultPEMs,
				saName:          testName,
				saNamespace:     testNamespace,
				aliasNameSource: aliasNameSourceSAName,
			},
			expectedAliasName: fmt.Sprintf("%s/%s", testNamespace, testName),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			b, storage := setupBackend(t, tc.config)

			req := &logical.Request{
				Operation: logical.AliasLookaheadOperation,
				Path:      "login",
				Storage:   storage,
				Data: map[string]interface{}{
					"jwt":  tc.jwt,
					"role": tc.role,
				},
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.1",
				},
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if tc.wantErr != nil {
				var actual error
				if err != nil {
					actual = err
				} else if resp != nil && resp.IsError() {
					actual = resp.Error()
				} else {
					t.Fatalf("expected error")
				}

				if tc.wantErr.Error() != actual.Error() {
					t.Fatalf("expected err %q, actual %q", tc.wantErr, actual)
				}
				if tc.wantErrCode != 0 {
					requireErrorCode(t, err, tc.wantErrCode)
				}
			} else {
				if err != nil || (resp != nil && resp.IsError()) {
					t.Fatalf("err:%s resp:%#v\n", err, resp)
				}

				if resp.Auth.Alias.Name != tc.expectedAliasName {
					t.Fatalf("expected Alias.Name %s, actual %s", tc.expectedAliasName, resp.Auth.Alias.Name)
				}
			}
		})
	}
}

func TestLoginIssValidation(t *testing.T) {
	config := defaultTestBackendConfig()
	b, storage := setupBackend(t, config)

	// test iss validation enabled with default "kubernetes/serviceaccount" issuer
	data := map[string]interface{}{
		"kubernetes_host":        "host",
		"kubernetes_ca_cert":     testCACert,
		"disable_iss_validation": false,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test successful login with default issuer
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	// test iss validation enabled with explicitly defined issuer
	data = map[string]interface{}{
		"kubernetes_host":        "host",
		"kubernetes_ca_cert":     testCACert,
		"disable_iss_validation": false,
		"issuer":                 "kubernetes/serviceaccount",
		"pem_keys":               testDefaultPEMs,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test successful login with explicitly defined issuer
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test iss validation enabled with custom issuer
	data = map[string]interface{}{
		"kubernetes_host":        "host",
		"kubernetes_ca_cert":     testCACert,
		"disable_iss_validation": false,
		"issuer":                 "custom-issuer",
		"pem_keys":               testDefaultPEMs,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test login fail with enabled iss validation and custom issuer
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != `invalid issuer (iss) claim` {
		t.Fatalf("unexpected error: %s", err)
	}

	// test iss validation disabled with custom issuer
	data = map[string]interface{}{
		"kubernetes_host":        "host",
		"kubernetes_ca_cert":     testCACert,
		"disable_iss_validation": true,
		"issuer":                 "custom-issuer",
		"pem_keys":               testDefaultPEMs,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	// test login success with disabled iss validation and custom issuer
	data = map[string]interface{}{
		"role": "plugin-test",
		"jwt":  jwtGoodDataToken,
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
}

func TestLoginProjectedToken(t *testing.T) {
	config := defaultTestBackendConfig()
	b, storage := setupBackend(t, config)

	// update backend to accept "default" bound account name
	data := map[string]interface{}{
		"bound_service_account_names":      fmt.Sprintf("%s,default", testName),
		"bound_service_account_namespaces": testNamespace,
		"policies":                         "test",
		"period":                           "3s",
		"ttl":                              "1s",
		"num_uses":                         12,
		"max_ttl":                          "5s",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/plugin-test",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	roleNameError := fmt.Errorf("invalid role name %q", "plugin-test-x")

	testCases := map[string]struct {
		role        string
		jwt         string
		tokenReview tokenReviewFactory
		e           error
	}{
		"normal": {
			role:        "plugin-test",
			jwt:         jwtGoodDataToken,
			tokenReview: testMockTokenReviewFactory,
		},
		"fail": {
			role:        "plugin-test-x",
			jwt:         jwtGoodDataToken,
			tokenReview: testMockTokenReviewFactory,
			e:           roleNameError,
		},
		"projected-token": {
			role:        "plugin-test",
			jwt:         jwtProjectedData,
			tokenReview: testProjectedMockTokenReviewFactory,
		},
		"projected-token-expired": {
			role:        "plugin-test",
			jwt:         jwtProjectedDataExpired,
			tokenReview: testProjectedMockTokenReviewFactory,
			e:           errors.New("invalid expiration time (exp) claim: token is expired"),
		},
		"projected-token-invalid-role": {
			role:        "plugin-test-x",
			jwt:         jwtProjectedData,
			tokenReview: testProjectedMockTokenReviewFactory,
			e:           roleNameError,
		},
	}

	for k, tc := range testCases {
		t.Run(k, func(t *testing.T) {
			data := map[string]interface{}{
				"role": tc.role,
				"jwt":  tc.jwt,
			}

			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "login",
				Storage:   storage,
				Data:      data,
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.1",
				},
			}

			b.(*kubeAuthBackend).reviewFactory = tc.tokenReview

			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil && tc.e == nil {
				t.Fatalf("unexpected err: (%s) resp:%#v\n", err, resp)
			}
			if err == nil && !resp.IsError() && tc.e != nil {
				t.Fatalf("expected error but found none: (%s) resp: %#v\n", tc.e, resp)
			}
			if resp != nil && resp.IsError() {
				if tc.e == nil {
					t.Fatalf("unexpected err: (%s)\n", resp.Error())
				}
				if tc.e.Error() != resp.Error().Error() {
					t.Fatalf("error mismatch in response, expected (%s) got (%s)", tc.e, resp.Error())
				}
			}
			if resp == nil && err != nil {
				if tc.e == nil {
					t.Fatalf("unexpected err: (%s)", err)
				}
				if tc.e.Error() != err.Error() {
					t.Fatalf("error mismatch, expected (%s) got (%s)", tc.e, err)
				}
			}
		})
	}
}

func TestAliasLookAheadProjectedToken(t *testing.T) {
	config := defaultTestBackendConfig()
	config.saName = "default"
	b, storage := setupBackend(t, config)

	data := map[string]interface{}{
		"jwt":  jwtProjectedData,
		"role": "plugin-test",
	}

	req := &logical.Request{
		Operation: logical.AliasLookaheadOperation,
		Path:      "login",
		Storage:   storage,
		Data:      data,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Auth.Alias.Name != testProjectedUID {
		t.Fatalf("Unexpected UID: %s", resp.Auth.Alias.Name)
	}
}

func Test_kubeAuthBackend_getAliasName(t *testing.T) {
	expectedErr := fmt.Errorf("service account namespace and name must be set")
	issuerDefault := "kubernetes/serviceaccount"
	issuerProjected := "https://kubernetes.default.svc.cluster.local"

	tests := []struct {
		name        string
		role        *roleStorageEntry
		signRequest *jwtSignTestRequest
		want        string
		wantErr     bool
	}{
		{
			name: "default",
			role: &roleStorageEntry{
				AliasNameSource: aliasNameSourceDefault,
			},
			signRequest: &jwtSignTestRequest{
				issuer:    issuerDefault,
				ns:        "default",
				sa:        "sa",
				uid:       testUID,
				projected: false,
			},
			want:    testUID,
			wantErr: false,
		},
		{
			name: "default-sa-uid",
			role: &roleStorageEntry{
				AliasNameSource: aliasNameSourceSAUid,
			},
			signRequest: &jwtSignTestRequest{
				issuer:    issuerDefault,
				ns:        "default",
				sa:        "sa",
				uid:       testUID,
				projected: false,
			},
			want:    testUID,
			wantErr: false,
		},
		{
			name: "default-sa-name",
			role: &roleStorageEntry{
				AliasNameSource: aliasNameSourceSAName,
			},
			signRequest: &jwtSignTestRequest{
				issuer:    issuerDefault,
				ns:        "default",
				sa:        "sa",
				projected: false,
			},
			want:    fmt.Sprintf("%s/%s", "default", "sa"),
			wantErr: false,
		},
		{
			name: "invalid-default-empty-ns",
			role: &roleStorageEntry{
				AliasNameSource: aliasNameSourceSAName,
			},
			signRequest: &jwtSignTestRequest{
				issuer:    issuerProjected,
				ns:        "",
				sa:        "sa2",
				projected: false,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "invalid-default-empty-sa",
			role: &roleStorageEntry{
				AliasNameSource: aliasNameSourceSAName,
			},
			signRequest: &jwtSignTestRequest{
				issuer:    issuerProjected,
				ns:        "default",
				sa:        "",
				projected: false,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "projected",
			role: &roleStorageEntry{
				AliasNameSource: aliasNameSourceDefault,
			},
			signRequest: &jwtSignTestRequest{
				issuer:    issuerProjected,
				ns:        "default",
				sa:        "sa",
				uid:       testProjectedUID,
				projected: true,
			},
			want:    testProjectedUID,
			wantErr: false,
		},
		{
			name: "projected-sa-uid",
			role: &roleStorageEntry{
				AliasNameSource: aliasNameSourceSAUid,
			},
			signRequest: &jwtSignTestRequest{
				issuer:    issuerProjected,
				ns:        "default",
				sa:        "sa",
				uid:       testProjectedUID,
				projected: true,
			},
			want:    testProjectedUID,
			wantErr: false,
		},
		{
			name: "projected-sa-name",
			role: &roleStorageEntry{
				AliasNameSource: aliasNameSourceSAName,
			},
			signRequest: &jwtSignTestRequest{
				issuer:    issuerProjected,
				ns:        "ns1",
				sa:        "sa",
				projected: true,
			},
			want:    fmt.Sprintf("%s/%s", "ns1", "sa"),
			wantErr: false,
		},
		{
			name: "invalid-projected-empty-ns",
			role: &roleStorageEntry{
				AliasNameSource: aliasNameSourceSAName,
			},
			signRequest: &jwtSignTestRequest{
				issuer:    issuerProjected,
				ns:        "",
				sa:        "sa2",
				projected: true,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "invalid-projected-empty-sa",
			role: &roleStorageEntry{
				AliasNameSource: aliasNameSourceSAName,
			},
			signRequest: &jwtSignTestRequest{
				issuer:    issuerProjected,
				ns:        "default",
				sa:        "",
				projected: true,
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &kubeAuthBackend{}

			s, err := signTestJWTRequest(tt.signRequest)
			if err != nil {
				t.Fatal(err)
			}

			tok, err := josejwt.ParseSigned(s)
			if err != nil {
				t.Fatal(err)
			}
			claims := map[string]interface{}{}
			err = tok.UnsafeClaimsWithoutVerification(&claims)
			if err != nil {
				t.Fatal(err)
			}

			sa := &serviceAccount{}
			if err := mapstructure.Decode(claims, sa); err != nil {
				t.Fatal(err)
			}

			got, err := b.getAliasName(tt.role, sa)

			if tt.wantErr {
				if err == nil {
					t.Errorf("getAliasName() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(expectedErr, err) {
					t.Errorf("getAliasName() expected error = %v, actual %v", expectedErr, err)
				}
			}

			if got != tt.want {
				t.Errorf("getAliasName() got = %v, want %v", got, tt.want)
			}
		})
	}
}

type jwtSignTestRequest struct {
	ns        string
	sa        string
	uid       string
	projected bool
	issuer    string
	expired   bool
}

func (r *jwtSignTestRequest) getUID() string {
	var uid string
	if r.uid == "" {
		uid, _ = uuid.GenerateUUID()
		r.uid = uid
	}

	return r.uid
}

func signTestJWTRequest(req *jwtSignTestRequest) (string, error) {
	var claims map[string]interface{}
	if req.projected {
		claims = projectedJWTTestClaims(req)
	} else {
		claims = defaultJWTTestClaims(req)
	}

	return signTestJWT(claims)
}

func jwtStandardTestClaims(req *jwtSignTestRequest) map[string]interface{} {
	now := time.Now()
	var horizon int64 = 86400
	if req.expired {
		horizon = horizon * -1
	}
	return map[string]interface{}{
		"iat": now.Unix(),
		"exp": now.Unix() + horizon,
		"iss": req.issuer,
	}
}

func projectedJWTTestClaims(req *jwtSignTestRequest) map[string]interface{} {
	type testToken struct {
		Namespace      string         `json:"namespace"`
		Pod            *v1.ObjectMeta `json:"pod"`
		ServiceAccount *v1.ObjectMeta `json:"serviceaccount"`
	}

	uid := types.UID(req.getUID())
	claims := jwtStandardTestClaims(req)
	claims["aud"] = []string{"baz"}
	claims["kubernetes.io"] = testToken{
		Namespace: req.ns,
		Pod: &v1.ObjectMeta{
			Name: "pod",
			UID:  uid,
		},
		ServiceAccount: &v1.ObjectMeta{
			Name: req.sa,
			UID:  uid,
		},
	}
	return claims
}

func defaultJWTTestClaims(req *jwtSignTestRequest) map[string]interface{} {
	claims := jwtStandardTestClaims(req)
	claims["kubernetes.io/serviceaccount/namespace"] = req.ns
	claims["kubernetes.io/serviceaccount/service-account.name"] = req.sa
	claims["kubernetes.io/serviceaccount/service-account.uid"] = req.getUID()
	return claims
}

func signTestJWT(claims map[string]interface{}) (string, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return jwtSign(jwtES256Header, string(data), ecdsaPrivateKey), nil
}

func requireErrorCode(t *testing.T, err error, expectedCode int) {
	t.Helper()

	codedErr, ok := err.(logical.HTTPCodedError)
	switch {
	case ok && codedErr.Code() == expectedCode:
		// Happy case
	case !ok:
		t.Fatal("err was not logical.HTTPCodedError")
	default:
		t.Fatalf("wrong error code, expected %d, got %d", expectedCode, codedErr.Code())
	}
}

func TestResolveRole(t *testing.T) {
	b, storage := getBackend(t)
	role := "testrole"

	validRoleStorageEntry := &roleStorageEntry{
		TokenParams: tokenutil.TokenParams{
			TokenPolicies:   []string{"test"},
			TokenPeriod:     3 * time.Second,
			TokenTTL:        1 * time.Second,
			TokenMaxTTL:     5 * time.Second,
			TokenNumUses:    12,
			TokenBoundCIDRs: nil,
		},
		Policies:                 []string{"test"},
		Period:                   3 * time.Second,
		ServiceAccountNames:      []string{"name"},
		ServiceAccountNamespaces: []string{"namespace"},
		TTL:                      1 * time.Second,
		MaxTTL:                   5 * time.Second,
		NumUses:                  12,
		BoundCIDRs:               nil,
		AliasNameSource:          aliasNameSourceDefault,
	}

	entry, err := logical.StorageEntryJSON("role/"+role, validRoleStorageEntry)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	loginData := map[string]interface{}{
		"role": role,
	}
	loginReq := &logical.Request{
		Operation: logical.ResolveRoleOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := b.HandleRequest(context.Background(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["role"] != role {
		t.Fatalf("Role was not as expected. Expected %s, received %s", role, resp.Data["role"])
	}
}

func TestResolveRole_RoleDoesNotExist(t *testing.T) {
	b, storage := getBackend(t)
	role := "testrole"

	loginData := map[string]interface{}{
		"role": role,
	}
	loginReq := &logical.Request{
		Operation: logical.ResolveRoleOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := b.HandleRequest(context.Background(), loginReq)
	if resp == nil && !resp.IsError() {
		t.Fatalf("Response was not an error: err:%v resp:%#v", err, resp)
	}

	errString, ok := resp.Data["error"].(string)
	if !ok {
		t.Fatal("Error not part of response.")
	}

	if !strings.Contains(errString, "invalid role name") {
		t.Fatalf("Error was not due to invalid role name. Error: %s", errString)
	}
}
