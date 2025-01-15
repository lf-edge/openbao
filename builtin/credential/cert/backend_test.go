// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/go-sockaddr"

	"golang.org/x/net/http2"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	vaulthttp "github.com/openbao/openbao/http"

	"github.com/go-viper/mapstructure/v2"
	"github.com/openbao/openbao/builtin/logical/pki"
	logicaltest "github.com/openbao/openbao/helper/testhelpers/logical"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

const (
	serverCertPath = "test-fixtures/cacert.pem"
	serverKeyPath  = "test-fixtures/cakey.pem"
	serverCAPath   = serverCertPath

	testRootCACertPath1 = "test-fixtures/testcacert1.pem"
	testRootCAKeyPath1  = "test-fixtures/testcakey1.pem"
	testCertPath1       = "test-fixtures/testissuedcert4.pem"
	testKeyPath1        = "test-fixtures/testissuedkey4.pem"
	testIssuedCertCRL   = "test-fixtures/issuedcertcrl"

	testRootCACertPath2 = "test-fixtures/testcacert2.pem"
	testRootCAKeyPath2  = "test-fixtures/testcakey2.pem"
	testRootCertCRL     = "test-fixtures/cacert2crl"
)

func generateTestCertAndConnState(t *testing.T, template *x509.Certificate) (string, tls.ConnectionState, error) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "vault-cert-auth-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("test %s, temp dir %s", t.Name(), tempDir)
	caCertTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(262980 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatal(err)
	}
	caCertPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}
	err = os.WriteFile(filepath.Join(tempDir, "ca_cert.pem"), pem.EncodeToMemory(caCertPEMBlock), 0o755)
	if err != nil {
		t.Fatal(err)
	}
	marshaledCAKey, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	caKeyPEMBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: marshaledCAKey,
	}
	err = os.WriteFile(filepath.Join(tempDir, "ca_key.pem"), pem.EncodeToMemory(caKeyPEMBlock), 0o755)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	err = os.WriteFile(filepath.Join(tempDir, "cert.pem"), pem.EncodeToMemory(certPEMBlock), 0o755)
	if err != nil {
		t.Fatal(err)
	}
	marshaledKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEMBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: marshaledKey,
	}
	err = os.WriteFile(filepath.Join(tempDir, "key.pem"), pem.EncodeToMemory(keyPEMBlock), 0o755)
	if err != nil {
		t.Fatal(err)
	}
	connInfo, err := testConnState(filepath.Join(tempDir, "cert.pem"), filepath.Join(tempDir, "key.pem"), filepath.Join(tempDir, "ca_cert.pem"))
	return tempDir, connInfo, err
}

// Unlike testConnState, this method does not use the same 'tls.Config' objects for
// both dialing and listening. Instead, it runs the server without specifying its CA.
// But the client, presents the CA cert of the server to trust the server.
// The client can present a cert and key which is completely independent of server's CA.
// The connection state returned will contain the certificate presented by the client.
func connectionState(serverCAPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath string) (tls.ConnectionState, error) {
	serverKeyPair, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	// Prepare the listener configuration with server's key pair
	listenConf := &tls.Config{
		Certificates: []tls.Certificate{serverKeyPair},
		ClientAuth:   tls.RequestClientCert,
	}

	clientKeyPair, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	// Load the CA cert required by the client to authenticate the server.
	pem, err := os.ReadFile(serverCAPath)
	if err != nil {
		return tls.ConnectionState{}, fmt.Errorf("Error loading CA File: %w", err)
	}

	// Initialize the cert pool.
	serverCAs := x509.NewCertPool()

	// Append the CA certificates from the PEM file to the cert pool.
	ok := serverCAs.AppendCertsFromPEM(pem)
	if !ok {
		return tls.ConnectionState{}, fmt.Errorf("Error loading CA File: Couldn't parse PEM in: %s", serverCAPath)
	}
	// Prepare the dial configuration that the client uses to establish the connection.
	dialConf := &tls.Config{
		Certificates: []tls.Certificate{clientKeyPair},
		RootCAs:      serverCAs,
	}

	// Start the server.
	list, err := tls.Listen("tcp", "127.0.0.1:0", listenConf)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer list.Close()

	// Accept connections.
	serverErrors := make(chan error, 1)
	connState := make(chan tls.ConnectionState)
	go func() {
		defer close(connState)
		serverConn, err := list.Accept()
		if err != nil {
			serverErrors <- err
			close(serverErrors)
			return
		}
		defer serverConn.Close()

		// Read the ping
		buf := make([]byte, 4)
		_, err = serverConn.Read(buf)
		if (err != nil) && (err != io.EOF) {
			serverErrors <- err
			close(serverErrors)
			return
		}
		close(serverErrors)
		connState <- serverConn.(*tls.Conn).ConnectionState()
	}()

	// Establish a connection from the client side and write a few bytes.
	clientErrors := make(chan error, 1)
	go func() {
		addr := list.Addr().String()
		conn, err := tls.Dial("tcp", addr, dialConf)
		if err != nil {
			clientErrors <- err
			close(clientErrors)
			return
		}
		defer conn.Close()

		// Write ping
		_, err = conn.Write([]byte("ping"))
		if err != nil {
			clientErrors <- err
		}
		close(clientErrors)
	}()

	for err = range clientErrors {
		if err != nil {
			return tls.ConnectionState{}, fmt.Errorf("error in client goroutine:%v", err)
		}
	}

	for err = range serverErrors {
		if err != nil {
			return tls.ConnectionState{}, fmt.Errorf("error in server goroutine:%v", err)
		}
	}
	// Grab the current state
	return <-connState, nil
}

func TestBackend_PermittedDNSDomainsIntermediateCA(t *testing.T) {
	// Enable PKI secret engine and Cert auth method
	coreConfig := &vault.CoreConfig{
		DisableCache: true,
		Logger:       log.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{
			"cert": Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	var err error

	// Mount /pki as a root CA
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Set the cluster's certificate as the root CA in /pki
	pemBundleRootCA := string(cluster.CACertPEM) + string(cluster.CAKeyPEM)
	_, err = client.Logical().Write("pki/config/ca", map[string]interface{}{
		"pem_bundle": pemBundleRootCA,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mount /pki2 to operate as an intermediate CA
	err = client.Sys().Mount("pki2", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a CSR for the intermediate CA
	secret, err := client.Logical().Write("pki2/intermediate/generate/internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	intermediateCSR := secret.Data["csr"].(string)

	// Sign the intermediate CSR using /pki
	secret, err = client.Logical().Write("pki/root/sign-intermediate", map[string]interface{}{
		"permitted_dns_domains": ".example.com",
		"csr":                   intermediateCSR,
	})
	if err != nil {
		t.Fatal(err)
	}
	intermediateCertPEM := secret.Data["certificate"].(string)

	// Configure the intermediate cert as the CA in /pki2
	_, err = client.Logical().Write("pki2/intermediate/set-signed", map[string]interface{}{
		"certificate": intermediateCertPEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a role on the intermediate CA mount
	_, err = client.Logical().Write("pki2/roles/myvault-dot-com", map[string]interface{}{
		"allowed_domains":  "example.com",
		"allow_subdomains": "true",
		"max_ttl":          "5m",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Issue a leaf cert using the intermediate CA
	secret, err = client.Logical().Write("pki2/issue/myvault-dot-com", map[string]interface{}{
		"common_name": "cert.example.com",
		"format":      "pem",
		"ip_sans":     "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	leafCertPEM := secret.Data["certificate"].(string)
	leafCertKeyPEM := secret.Data["private_key"].(string)

	// Enable the cert auth method
	err = client.Sys().EnableAuthWithOptions("cert", &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Set the intermediate CA cert as a trusted certificate in the backend
	_, err = client.Logical().Write("auth/cert/certs/myvault-dot-com", map[string]interface{}{
		"display_name": "example.com",
		"policies":     "default",
		"certificate":  intermediateCertPEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create temporary files for CA cert, client cert and client cert key.
	// This is used to configure TLS in the api client.
	caCertFile, err := os.CreateTemp("", "caCert")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(caCertFile.Name())
	if _, err := caCertFile.Write([]byte(cluster.CACertPEM)); err != nil {
		t.Fatal(err)
	}
	if err := caCertFile.Close(); err != nil {
		t.Fatal(err)
	}

	leafCertFile, err := os.CreateTemp("", "leafCert")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(leafCertFile.Name())
	if _, err := leafCertFile.Write([]byte(leafCertPEM)); err != nil {
		t.Fatal(err)
	}
	if err := leafCertFile.Close(); err != nil {
		t.Fatal(err)
	}

	leafCertKeyFile, err := os.CreateTemp("", "leafCertKey")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(leafCertKeyFile.Name())
	if _, err := leafCertKeyFile.Write([]byte(leafCertKeyPEM)); err != nil {
		t.Fatal(err)
	}
	if err := leafCertKeyFile.Close(); err != nil {
		t.Fatal(err)
	}

	// This function is a copy-pasta from the NewTestCluster, with the
	// modification to reconfigure the TLS on the api client with the leaf
	// certificate generated above.
	getAPIClient := func(port int, tlsConfig *tls.Config) *api.Client {
		transport := cleanhttp.DefaultPooledTransport()
		transport.TLSClientConfig = tlsConfig.Clone()
		if err := http2.ConfigureTransport(transport); err != nil {
			t.Fatal(err)
		}
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// This can of course be overridden per-test by using its own client
				return fmt.Errorf("redirects not allowed in these tests")
			},
		}
		config := api.DefaultConfig()
		if config.Error != nil {
			t.Fatal(config.Error)
		}
		config.Address = fmt.Sprintf("https://127.0.0.1:%d", port)
		config.HttpClient = client

		// Set the above issued certificates as the client certificates
		config.ConfigureTLS(&api.TLSConfig{
			CACert:     caCertFile.Name(),
			ClientCert: leafCertFile.Name(),
			ClientKey:  leafCertKeyFile.Name(),
		})

		apiClient, err := api.NewClient(config)
		if err != nil {
			t.Fatal(err)
		}
		return apiClient
	}

	// Create a new api client with the desired TLS configuration
	newClient := getAPIClient(cores[0].Listeners[0].Address.Port, cores[0].TLSConfig())

	secret, err = newClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": "myvault-dot-com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Fatalf("expected a successful authentication")
	}

	// testing pathLoginRenew for cert auth
	oldAccessor := secret.Auth.Accessor
	newClient.SetToken(client.Token())
	secret, err = newClient.Logical().Write("auth/token/renew-accessor", map[string]interface{}{
		"accessor":  secret.Auth.Accessor,
		"increment": 3600,
	})
	if err != nil {
		t.Fatal(err)
	}

	if secret.Auth == nil || secret.Auth.ClientToken != "" || secret.Auth.LeaseDuration != 3600 || secret.Auth.Accessor != oldAccessor {
		t.Fatalf("unexpected accessor renewal")
	}
}

func TestBackend_MetadataBasedACLPolicy(t *testing.T) {
	// Start cluster with cert auth method enabled
	coreConfig := &vault.CoreConfig{
		DisableCache: true,
		Logger:       log.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{
			"cert": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	var err error

	// Enable the cert auth method
	err = client.Sys().EnableAuthWithOptions("cert", &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Enable metadata in aliases
	_, err = client.Logical().Write("auth/cert/config", map[string]interface{}{
		"enable_identity_alias_metadata": true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Retrieve its accessor id
	auths, err := client.Sys().ListAuth()
	if err != nil {
		t.Fatal(err)
	}

	var accessor string

	for _, auth := range auths {
		if auth.Type == "cert" {
			accessor = auth.Accessor
		}
	}

	if accessor == "" {
		t.Fatal("failed to find cert auth accessor")
	}

	// Write ACL policy
	err = client.Sys().PutPolicy("metadata-based", fmt.Sprintf(`
path "kv/cn/{{identity.entity.aliases.%s.metadata.common_name}}" {
	capabilities = ["read"]
}
path "kv/ext/{{identity.entity.aliases.%s.metadata.2-1-1-1}}" {
	capabilities = ["read"]
}
`, accessor, accessor))
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	ca, err := os.ReadFile("test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Set the trusted certificate in the backend
	_, err = client.Logical().Write("auth/cert/certs/test", map[string]interface{}{
		"display_name":                "test",
		"policies":                    "metadata-based",
		"certificate":                 string(ca),
		"allowed_metadata_extensions": "2.1.1.1,1.2.3.45",
	})
	if err != nil {
		t.Fatal(err)
	}

	// This function is a copy-paste from the NewTestCluster, with the
	// modification to reconfigure the TLS on the api client with a
	// specific client certificate.
	getAPIClient := func(port int, tlsConfig *tls.Config) *api.Client {
		transport := cleanhttp.DefaultPooledTransport()
		transport.TLSClientConfig = tlsConfig.Clone()
		if err := http2.ConfigureTransport(transport); err != nil {
			t.Fatal(err)
		}
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// This can of course be overridden per-test by using its own client
				return fmt.Errorf("redirects not allowed in these tests")
			},
		}
		config := api.DefaultConfig()
		if config.Error != nil {
			t.Fatal(config.Error)
		}
		config.Address = fmt.Sprintf("https://127.0.0.1:%d", port)
		config.HttpClient = client

		// Set the client certificates
		config.ConfigureTLS(&api.TLSConfig{
			CACertBytes: cluster.CACertPEM,
			ClientCert:  "test-fixtures/root/rootcawextcert.pem",
			ClientKey:   "test-fixtures/root/rootcawextkey.pem",
		})

		apiClient, err := api.NewClient(config)
		if err != nil {
			t.Fatal(err)
		}
		return apiClient
	}

	// Create a new api client with the desired TLS configuration
	newClient := getAPIClient(cores[0].Listeners[0].Address.Port, cores[0].TLSConfig())

	var secret *api.Secret

	secret, err = newClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Fatalf("expected a successful authentication")
	}

	// Check paths guarded by ACL policy
	newClient.SetToken(secret.Auth.ClientToken)

	_, err = newClient.Logical().Read("kv/cn/example.com")
	if err != nil {
		t.Fatal(err)
	}

	_, err = newClient.Logical().Read("kv/cn/not.example.com")
	if err == nil {
		t.Fatal("expected access denied")
	}

	_, err = newClient.Logical().Read("kv/ext/A UTF8String Extension")
	if err != nil {
		t.Fatal(err)
	}

	_, err = newClient.Logical().Read("kv/ext/bar")
	if err == nil {
		t.Fatal("expected access denied")
	}
}

func TestBackend_NonCAExpiry(t *testing.T) {
	var resp *logical.Response
	var err error

	// Create a self-signed certificate and issue a leaf certificate using the
	// CA cert
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Subject: pkix.Name{
			CommonName:         "localhost",
			Organization:       []string{"hashicorp"},
			OrganizationalUnit: []string{"vault"},
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(50 * time.Second),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
	}

	// Set IP SAN
	parsedIP := net.ParseIP("127.0.0.1")
	if parsedIP == nil {
		t.Fatalf("failed to create parsed IP")
	}
	template.IPAddresses = []net.IP{parsedIP}

	// Private key for CA cert
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Marshalling to be able to create PEM file
	caPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(caPrivateKey)

	caPublicKey := &caPrivateKey.PublicKey

	template.IsCA = true

	caCertBytes, err := x509.CreateCertificate(rand.Reader, template, template, caPublicKey, caPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatal(err)
	}

	parsedCaBundle := &certutil.ParsedCertBundle{
		Certificate:      caCert,
		CertificateBytes: caCertBytes,
		PrivateKeyBytes:  caPrivateKeyBytes,
		PrivateKeyType:   certutil.RSAPrivateKey,
	}

	caCertBundle, err := parsedCaBundle.ToCertBundle()
	if err != nil {
		t.Fatal(err)
	}

	caCertFile, err := os.CreateTemp("", "caCert")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(caCertFile.Name())

	if _, err := caCertFile.Write([]byte(caCertBundle.Certificate)); err != nil {
		t.Fatal(err)
	}
	if err := caCertFile.Close(); err != nil {
		t.Fatal(err)
	}

	caKeyFile, err := os.CreateTemp("", "caKey")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(caKeyFile.Name())

	if _, err := caKeyFile.Write([]byte(caCertBundle.PrivateKey)); err != nil {
		t.Fatal(err)
	}
	if err := caKeyFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Prepare template for non-CA cert

	template.IsCA = false
	template.SerialNumber = big.NewInt(5678)

	template.KeyUsage = x509.KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign)
	issuedPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	issuedPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(issuedPrivateKey)

	issuedPublicKey := &issuedPrivateKey.PublicKey

	// Keep a short certificate lifetime so logins can be tested both when
	// cert is valid and when it gets expired
	template.NotBefore = time.Now().Add(-2 * time.Second)
	template.NotAfter = time.Now().Add(3 * time.Second)

	issuedCertBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, issuedPublicKey, caPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	issuedCert, err := x509.ParseCertificate(issuedCertBytes)
	if err != nil {
		t.Fatal(err)
	}

	parsedIssuedBundle := &certutil.ParsedCertBundle{
		Certificate:      issuedCert,
		CertificateBytes: issuedCertBytes,
		PrivateKeyBytes:  issuedPrivateKeyBytes,
		PrivateKeyType:   certutil.RSAPrivateKey,
	}

	issuedCertBundle, err := parsedIssuedBundle.ToCertBundle()
	if err != nil {
		t.Fatal(err)
	}

	issuedCertFile, err := os.CreateTemp("", "issuedCert")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(issuedCertFile.Name())

	if _, err := issuedCertFile.Write([]byte(issuedCertBundle.Certificate)); err != nil {
		t.Fatal(err)
	}
	if err := issuedCertFile.Close(); err != nil {
		t.Fatal(err)
	}

	issuedKeyFile, err := os.CreateTemp("", "issuedKey")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(issuedKeyFile.Name())

	if _, err := issuedKeyFile.Write([]byte(issuedCertBundle.PrivateKey)); err != nil {
		t.Fatal(err)
	}
	if err := issuedKeyFile.Close(); err != nil {
		t.Fatal(err)
	}

	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	// Register the Non-CA certificate of the client key pair
	certData := map[string]interface{}{
		"certificate":  issuedCertBundle.Certificate,
		"policies":     "abc",
		"display_name": "cert1",
		"ttl":          10000,
	}
	certReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "certs/cert1",
		Storage:   storage,
		Data:      certData,
	}

	resp, err = b.HandleRequest(context.Background(), certReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Create connection state using the certificates generated
	connState, err := connectionState(caCertFile.Name(), caCertFile.Name(), caKeyFile.Name(), issuedCertFile.Name(), issuedKeyFile.Name())
	if err != nil {
		t.Fatalf("error testing connection state:%v", err)
	}

	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "login",
		Connection: &logical.Connection{
			ConnState: &connState,
		},
	}

	// Login when the certificate is still valid. Login should succeed.
	resp, err = b.HandleRequest(context.Background(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Wait until the certificate expires
	time.Sleep(5 * time.Second)

	// Login attempt after certificate expiry should fail
	resp, err = b.HandleRequest(context.Background(), loginReq)
	if err == nil {
		t.Fatalf("expected error due to expired certificate")
	}
}

func TestBackend_RegisteredNonCA_CRL(t *testing.T) {
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	nonCACert, err := os.ReadFile(testCertPath1)
	if err != nil {
		t.Fatal(err)
	}

	// Register the Non-CA certificate of the client key pair
	certData := map[string]interface{}{
		"certificate":  nonCACert,
		"policies":     "abc",
		"display_name": "cert1",
		"ttl":          10000,
	}
	certReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "certs/cert1",
		Storage:   storage,
		Data:      certData,
	}

	resp, err := b.HandleRequest(context.Background(), certReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Connection state is presenting the client Non-CA cert and its key.
	// This is exactly what is registered at the backend.
	connState, err := connectionState(serverCAPath, serverCertPath, serverKeyPath, testCertPath1, testKeyPath1)
	if err != nil {
		t.Fatalf("error testing connection state:%v", err)
	}
	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "login",
		Connection: &logical.Connection{
			ConnState: &connState,
		},
	}
	// Login should succeed.
	resp, err = b.HandleRequest(context.Background(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Register a CRL containing the issued client certificate used above.
	issuedCRL, err := os.ReadFile(testIssuedCertCRL)
	if err != nil {
		t.Fatal(err)
	}
	crlData := map[string]interface{}{
		"crl": issuedCRL,
	}
	crlReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "crls/issuedcrl",
		Data:      crlData,
	}
	resp, err = b.HandleRequest(context.Background(), crlReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Ensure the CRL shows up on a list.
	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Storage:   storage,
		Path:      "crls",
		Data:      map[string]interface{}{},
	}
	resp, err = b.HandleRequest(context.Background(), listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	if len(resp.Data) != 1 || len(resp.Data["keys"].([]string)) != 1 || resp.Data["keys"].([]string)[0] != "issuedcrl" {
		t.Fatalf("bad listing: resp:%v", resp)
	}

	// Attempt login with the same connection state but with the CRL registered
	resp, err = b.HandleRequest(context.Background(), loginReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected failure due to revoked certificate")
	}
}

func TestBackend_CRLs(t *testing.T) {
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	clientCA1, err := os.ReadFile(testRootCACertPath1)
	if err != nil {
		t.Fatal(err)
	}
	// Register the CA certificate of the client key pair
	certData := map[string]interface{}{
		"certificate":  clientCA1,
		"policies":     "abc",
		"display_name": "cert1",
		"ttl":          10000,
	}

	certReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "certs/cert1",
		Storage:   storage,
		Data:      certData,
	}

	resp, err := b.HandleRequest(context.Background(), certReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Connection state is presenting the client CA cert and its key.
	// This is exactly what is registered at the backend.
	connState, err := connectionState(serverCAPath, serverCertPath, serverKeyPath, testRootCACertPath1, testRootCAKeyPath1)
	if err != nil {
		t.Fatalf("error testing connection state:%v", err)
	}
	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "login",
		Connection: &logical.Connection{
			ConnState: &connState,
		},
	}
	resp, err = b.HandleRequest(context.Background(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Now, without changing the registered client CA cert, present from
	// the client side, a cert issued using the registered CA.
	connState, err = connectionState(serverCAPath, serverCertPath, serverKeyPath, testCertPath1, testKeyPath1)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	loginReq.Connection.ConnState = &connState

	// Attempt login with the updated connection
	resp, err = b.HandleRequest(context.Background(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Register a CRL containing the issued client certificate used above.
	issuedCRL, err := os.ReadFile(testIssuedCertCRL)
	if err != nil {
		t.Fatal(err)
	}
	crlData := map[string]interface{}{
		"crl": issuedCRL,
	}

	crlReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "crls/issuedcrl",
		Data:      crlData,
	}
	resp, err = b.HandleRequest(context.Background(), crlReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Attempt login with the revoked certificate.
	resp, err = b.HandleRequest(context.Background(), loginReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected failure due to revoked certificate")
	}

	// Register a different client CA certificate.
	clientCA2, err := os.ReadFile(testRootCACertPath2)
	if err != nil {
		t.Fatal(err)
	}
	certData["certificate"] = clientCA2
	resp, err = b.HandleRequest(context.Background(), certReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Test login using a different client CA cert pair.
	connState, err = connectionState(serverCAPath, serverCertPath, serverKeyPath, testRootCACertPath2, testRootCAKeyPath2)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	loginReq.Connection.ConnState = &connState

	// Attempt login with the updated connection
	resp, err = b.HandleRequest(context.Background(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Register a CRL containing the root CA certificate used above.
	rootCRL, err := os.ReadFile(testRootCertCRL)
	if err != nil {
		t.Fatal(err)
	}
	crlData["crl"] = rootCRL
	resp, err = b.HandleRequest(context.Background(), crlReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	// Attempt login with the same connection state but with the CRL registered
	resp, err = b.HandleRequest(context.Background(), loginReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected failure due to revoked certificate")
	}
}

func testFactory(t *testing.T) logical.Backend {
	storage := &logical.InmemStorage{}
	b, err := Factory(context.Background(), &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: 1000 * time.Second,
			MaxLeaseTTLVal:     1800 * time.Second,
		},
		StorageView: storage,
	})
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if err := b.Initialize(context.Background(), &logical.InitializationRequest{
		Storage: storage,
	}); err != nil {
		t.Fatalf("error: %s", err)
	}
	return b
}

// Test the certificates being registered to the backend
func TestBackend_CertWrites(t *testing.T) {
	// CA cert
	ca1, err := os.ReadFile("test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Non CA Cert
	ca2, err := os.ReadFile("test-fixtures/keys/cert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Non CA cert without TLS web client authentication
	ca3, err := os.ReadFile("test-fixtures/noclientauthcert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	tc := logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "aaa", ca1, "foo", allowed{}, false),
			testAccStepCert(t, "bbb", ca2, "foo", allowed{}, false),
			testAccStepCert(t, "ccc", ca3, "foo", allowed{}, true),
		},
	}
	tc.Steps = append(tc.Steps, testAccStepListCerts(t, []string{"aaa", "bbb"})...)
	logicaltest.Test(t, tc)
}

// Test a client trusted by a CA
func TestBackend_basic_CA(t *testing.T) {
	connState, err := testConnState("test-fixtures/keys/cert.pem",
		"test-fixtures/keys/key.pem", "test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile("test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca, "foo", allowed{}, false),
			testAccStepLogin(t, connState),
			testAccStepCertLease(t, "web", ca, "foo"),
			testAccStepCertTTL(t, "web", ca, "foo"),
			testAccStepLogin(t, connState),
			testAccStepCertMaxTTL(t, "web", ca, "foo"),
			testAccStepLogin(t, connState),
			testAccStepCertNoLease(t, "web", ca, "foo"),
			testAccStepLoginDefaultLease(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "*.example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "*.invalid.com"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test CRL behavior
func TestBackend_Basic_CRLs(t *testing.T) {
	connState, err := testConnState("test-fixtures/keys/cert.pem",
		"test-fixtures/keys/key.pem", "test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile("test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	crl, err := os.ReadFile("test-fixtures/root/root.crl")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCertNoLease(t, "web", ca, "foo"),
			testAccStepLoginDefaultLease(t, connState),
			testAccStepAddCRL(t, crl, connState),
			testAccStepReadCRL(t, connState),
			testAccStepLoginInvalid(t, connState),
			testAccStepDeleteCRL(t, connState),
			testAccStepLoginDefaultLease(t, connState),
		},
	})
}

// Test a self-signed client (root CA) that is trusted
func TestBackend_basic_singleCert(t *testing.T) {
	connState, err := testConnState("test-fixtures/root/rootcacert.pem",
		"test-fixtures/root/rootcakey.pem", "test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile("test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca, "foo", allowed{}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "invalid"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "1.2.3.4:invalid"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

func TestBackend_common_name_singleCert(t *testing.T) {
	connState, err := testConnState("test-fixtures/root/rootcacert.pem",
		"test-fixtures/root/rootcakey.pem", "test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile("test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca, "foo", allowed{}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{common_names: "example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{common_names: "invalid"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "1.2.3.4:invalid"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test a self-signed client with custom ext (root CA) that is trusted
func TestBackend_ext_singleCert(t *testing.T) {
	connState, err := testConnState(
		"test-fixtures/root/rootcawextcert.pem",
		"test-fixtures/root/rootcawextkey.pem",
		"test-fixtures/root/rootcacert.pem",
	)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile("test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:A UTF8String Extension"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:*,2.1.1.2:A UTF8*"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "1.2.3.45:*"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:*,2.1.1.2:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{ext: "2.1.1.1:,2.1.1.2:*"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "example.com", ext: "2.1.1.1:A UTF8String Extension"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "example.com", ext: "2.1.1.1:*,2.1.1.2:A UTF8*"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "example.com", ext: "1.2.3.45:*"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "example.com", ext: "2.1.1.1:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "example.com", ext: "2.1.1.1:*,2.1.1.2:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "invalid", ext: "2.1.1.1:A UTF8String Extension"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "invalid", ext: "2.1.1.1:*,2.1.1.2:A UTF8*"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "invalid", ext: "1.2.3.45:*"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "invalid", ext: "2.1.1.1:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{names: "invalid", ext: "2.1.1.1:*,2.1.1.2:The Wrong Value"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepReadConfig(t, config{EnableIdentityAliasMetadata: false}, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{metadata_ext: "2.1.1.1,1.2.3.45"}, false),
			testAccStepLoginWithMetadata(t, connState, "web", map[string]string{"2-1-1-1": "A UTF8String Extension"}, false),
			testAccStepCert(t, "web", ca, "foo", allowed{metadata_ext: "1.2.3.45"}, false),
			testAccStepLoginWithMetadata(t, connState, "web", map[string]string{}, false),
			testAccStepSetConfig(t, config{EnableIdentityAliasMetadata: true}, connState),
			testAccStepReadConfig(t, config{EnableIdentityAliasMetadata: true}, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{metadata_ext: "2.1.1.1,1.2.3.45"}, false),
			testAccStepLoginWithMetadata(t, connState, "web", map[string]string{"2-1-1-1": "A UTF8String Extension"}, true),
			testAccStepCert(t, "web", ca, "foo", allowed{metadata_ext: "1.2.3.45"}, false),
			testAccStepLoginWithMetadata(t, connState, "web", map[string]string{}, true),
		},
	})
}

// Test a self-signed client with URI alt names (root CA) that is trusted
func TestBackend_dns_singleCert(t *testing.T) {
	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames:    []string{"example.com"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		SerialNumber: big.NewInt(mathrand.Int63()),
		NotBefore:    time.Now().Add(-30 * time.Second),
		NotAfter:     time.Now().Add(262980 * time.Hour),
	}

	tempDir, connState, err := generateTestCertAndConnState(t, certTemplate)
	if tempDir != "" {
		defer os.RemoveAll(tempDir)
	}
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile(filepath.Join(tempDir, "ca_cert.pem"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca, "foo", allowed{dns: "example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{dns: "*ample.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{dns: "notincert.com"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{dns: "abc"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{dns: "*.example.com"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test a self-signed client with URI alt names (root CA) that is trusted
func TestBackend_email_singleCert(t *testing.T) {
	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		EmailAddresses: []string{"valid@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		SerialNumber: big.NewInt(mathrand.Int63()),
		NotBefore:    time.Now().Add(-30 * time.Second),
		NotAfter:     time.Now().Add(262980 * time.Hour),
	}

	tempDir, connState, err := generateTestCertAndConnState(t, certTemplate)
	if tempDir != "" {
		defer os.RemoveAll(tempDir)
	}
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile(filepath.Join(tempDir, "ca_cert.pem"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca, "foo", allowed{emails: "valid@example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{emails: "*@example.com"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{emails: "invalid@notincert.com"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{emails: "abc"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{emails: "*.example.com"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test a self-signed client with OU (root CA) that is trusted
func TestBackend_organizationalUnit_singleCert(t *testing.T) {
	connState, err := testConnState(
		"test-fixtures/root/rootcawoucert.pem",
		"test-fixtures/root/rootcawoukey.pem",
		"test-fixtures/root/rootcawoucert.pem",
	)
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile("test-fixtures/root/rootcawoucert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca, "foo", allowed{organizational_units: "engineering"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{organizational_units: "eng*"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{organizational_units: "engineering,finance"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{organizational_units: "foo"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test a self-signed client with URI alt names (root CA) that is trusted
func TestBackend_uri_singleCert(t *testing.T) {
	u, err := url.Parse("spiffe://example.com/host")
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		DNSNames:    []string{"example.com"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		URIs:        []*url.URL{u},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		SerialNumber: big.NewInt(mathrand.Int63()),
		NotBefore:    time.Now().Add(-30 * time.Second),
		NotAfter:     time.Now().Add(262980 * time.Hour),
	}

	tempDir, connState, err := generateTestCertAndConnState(t, certTemplate)
	if tempDir != "" {
		defer os.RemoveAll(tempDir)
	}
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile(filepath.Join(tempDir, "ca_cert.pem"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "web", ca, "foo", allowed{uris: "spiffe://example.com/*"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{uris: "spiffe://example.com/host"}, false),
			testAccStepLogin(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{uris: "spiffe://example.com/invalid"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{uris: "abc"}, false),
			testAccStepLoginInvalid(t, connState),
			testAccStepCert(t, "web", ca, "foo", allowed{uris: "http://www.google.com"}, false),
			testAccStepLoginInvalid(t, connState),
		},
	})
}

// Test against a collection of matching and non-matching rules
func TestBackend_mixed_constraints(t *testing.T) {
	connState, err := testConnState("test-fixtures/keys/cert.pem",
		"test-fixtures/keys/key.pem", "test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile("test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepCert(t, "1unconstrained", ca, "foo", allowed{}, false),
			testAccStepCert(t, "2matching", ca, "foo", allowed{names: "*.example.com,whatever"}, false),
			testAccStepCert(t, "3invalid", ca, "foo", allowed{names: "invalid"}, false),
			testAccStepLogin(t, connState),
			// Assumes CertEntries are processed in alphabetical order (due to store.List), so we only match 2matching if 1unconstrained doesn't match
			testAccStepLoginWithName(t, connState, "2matching"),
			testAccStepLoginWithNameInvalid(t, connState, "3invalid"),
		},
	})
}

// Test an untrusted client
func TestBackend_untrusted(t *testing.T) {
	connState, err := testConnState("test-fixtures/keys/cert.pem",
		"test-fixtures/keys/key.pem", "test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: testFactory(t),
		Steps: []logicaltest.TestStep{
			testAccStepLoginInvalid(t, connState),
		},
	})
}

func TestBackend_validCIDR(t *testing.T) {
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	connState, err := testConnState("test-fixtures/keys/cert.pem",
		"test-fixtures/keys/key.pem", "test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile("test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	name := "web"
	boundCIDRs := []string{"127.0.0.1", "128.252.0.0/16"}

	addCertReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":         string(ca),
			"policies":            "foo",
			"display_name":        name,
			"allowed_names":       "",
			"required_extensions": "",
			"lease":               1000,
			"bound_cidrs":         boundCIDRs,
		},
		Storage:    storage,
		Connection: &logical.Connection{ConnState: &connState},
	}

	_, err = b.HandleRequest(context.Background(), addCertReq)
	if err != nil {
		t.Fatal(err)
	}

	readCertReq := &logical.Request{
		Operation:  logical.ReadOperation,
		Path:       "certs/" + name,
		Storage:    storage,
		Connection: &logical.Connection{ConnState: &connState},
	}

	readResult, err := b.HandleRequest(context.Background(), readCertReq)
	if err != nil {
		t.Fatal(err)
	}
	cidrsResult := readResult.Data["bound_cidrs"].([]*sockaddr.SockAddrMarshaler)

	if cidrsResult[0].String() != boundCIDRs[0] ||
		cidrsResult[1].String() != boundCIDRs[1] {
		t.Fatalf("bound_cidrs couldn't be set correctly, EXPECTED: %v, ACTUAL: %v", boundCIDRs, cidrsResult)
	}

	loginReq := &logical.Request{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		Data: map[string]interface{}{
			"name": name,
		},
		Storage:    storage,
		Connection: &logical.Connection{ConnState: &connState},
	}

	// override the remote address with an IPV4 that is authorized
	loginReq.Connection.RemoteAddr = "127.0.0.1/32"

	_, err = b.HandleRequest(context.Background(), loginReq)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestBackend_invalidCIDR(t *testing.T) {
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	connState, err := testConnState("test-fixtures/keys/cert.pem",
		"test-fixtures/keys/key.pem", "test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile("test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	name := "web"

	addCertReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":         string(ca),
			"policies":            "foo",
			"display_name":        name,
			"allowed_names":       "",
			"required_extensions": "",
			"lease":               1000,
			"bound_cidrs":         []string{"127.0.0.1/32", "128.252.0.0/16"},
		},
		Storage:    storage,
		Connection: &logical.Connection{ConnState: &connState},
	}

	_, err = b.HandleRequest(context.Background(), addCertReq)
	if err != nil {
		t.Fatal(err)
	}

	loginReq := &logical.Request{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		Data: map[string]interface{}{
			"name": name,
		},
		Storage:    storage,
		Connection: &logical.Connection{ConnState: &connState},
	}

	// override the remote address with an IPV4 that isn't authorized
	loginReq.Connection.RemoteAddr = "127.0.0.1/8"

	_, err = b.HandleRequest(context.Background(), loginReq)
	if err == nil {
		t.Fatal("expected \"ERROR: permission denied\"")
	}
}

func testAccStepAddCRL(t *testing.T, crl []byte, connState tls.ConnectionState) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "crls/test",
		ConnState: &connState,
		Data: map[string]interface{}{
			"crl": crl,
		},
	}
}

func testAccStepReadCRL(t *testing.T, connState tls.ConnectionState) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "crls/test",
		ConnState: &connState,
		Check: func(resp *logical.Response) error {
			crlInfo := CRLInfo{}
			err := mapstructure.Decode(resp.Data, &crlInfo)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if len(crlInfo.Serials) != 1 {
				t.Fatalf("bad: expected CRL with length 1, got %d", len(crlInfo.Serials))
			}
			if _, ok := crlInfo.Serials["637101449987587619778072672905061040630001617053"]; !ok {
				t.Fatalf("bad: expected serial number not found in CRL")
			}
			return nil
		},
	}
}

func testAccStepDeleteCRL(t *testing.T, connState tls.ConnectionState) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.DeleteOperation,
		Path:      "crls/test",
		ConnState: &connState,
	}
}

func testAccStepSetConfig(t *testing.T, conf config, connState tls.ConnectionState) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "config",
		ConnState: &connState,
		Data: map[string]interface{}{
			"enable_identity_alias_metadata": conf.EnableIdentityAliasMetadata,
		},
	}
}

func testAccStepReadConfig(t *testing.T, conf config, connState tls.ConnectionState) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "config",
		ConnState: &connState,
		Check: func(resp *logical.Response) error {
			value, ok := resp.Data["enable_identity_alias_metadata"]
			if !ok {
				t.Fatalf("enable_identity_alias_metadata not found in response")
			}

			b, ok := value.(bool)
			if !ok {
				t.Fatalf("bad: expected enable_identity_alias_metadata to be a bool")
			}

			if b != conf.EnableIdentityAliasMetadata {
				t.Fatalf("bad: expected enable_identity_alias_metadata to be %t, got %t", conf.EnableIdentityAliasMetadata, b)
			}

			return nil
		},
	}
}

func testAccStepLogin(t *testing.T, connState tls.ConnectionState) logicaltest.TestStep {
	return testAccStepLoginWithName(t, connState, "")
}

func testAccStepLoginWithName(t *testing.T, connState tls.ConnectionState, certName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		Check: func(resp *logical.Response) error {
			if resp.Auth.TTL != 1000*time.Second {
				t.Fatalf("bad lease length: %#v", resp.Auth)
			}

			if certName != "" && resp.Auth.DisplayName != ("mnt-"+certName) {
				t.Fatalf("matched the wrong cert: %#v", resp.Auth.DisplayName)
			}

			fn := logicaltest.TestCheckAuth([]string{"default", "foo"})
			return fn(resp)
		},
		Data: map[string]interface{}{
			"name": certName,
		},
	}
}

func testAccStepLoginDefaultLease(t *testing.T, connState tls.ConnectionState) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		Check: func(resp *logical.Response) error {
			if resp.Auth.TTL != 1000*time.Second {
				t.Fatalf("bad lease length: %#v", resp.Auth)
			}

			fn := logicaltest.TestCheckAuth([]string{"default", "foo"})
			return fn(resp)
		},
	}
}

func testAccStepLoginWithMetadata(t *testing.T, connState tls.ConnectionState, certName string, metadata map[string]string, expectAliasMetadata bool) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		Check: func(resp *logical.Response) error {
			// Check for fixed metadata too
			metadata["cert_name"] = certName
			metadata["common_name"] = connState.PeerCertificates[0].Subject.CommonName
			metadata["serial_number"] = connState.PeerCertificates[0].SerialNumber.String()
			metadata["subject_key_id"] = certutil.GetHexFormatted(connState.PeerCertificates[0].SubjectKeyId, ":")
			metadata["authority_key_id"] = certutil.GetHexFormatted(connState.PeerCertificates[0].AuthorityKeyId, ":")

			for key, expected := range metadata {
				value, ok := resp.Auth.Metadata[key]
				if !ok {
					t.Fatalf("missing metadata key: %s", key)
				}

				if value != expected {
					t.Fatalf("expected metadata key %s to equal %s, but got: %s", key, expected, value)
				}

				if expectAliasMetadata {
					value, ok = resp.Auth.Alias.Metadata[key]
					if !ok {
						t.Fatalf("missing alias metadata key: %s", key)
					}

					if value != expected {
						t.Fatalf("expected metadata key %s to equal %s, but got: %s", key, expected, value)
					}
				} else {
					if len(resp.Auth.Alias.Metadata) > 0 {
						t.Fatal("found alias metadata keys, but should not have any")
					}
				}
			}

			fn := logicaltest.TestCheckAuth([]string{"default", "foo"})
			return fn(resp)
		},
		Data: map[string]interface{}{
			"metadata": metadata,
		},
	}
}

func testAccStepLoginInvalid(t *testing.T, connState tls.ConnectionState) logicaltest.TestStep {
	return testAccStepLoginWithNameInvalid(t, connState, "")
}

func testAccStepLoginWithNameInvalid(t *testing.T, connState tls.ConnectionState, certName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.UpdateOperation,
		Path:            "login",
		Unauthenticated: true,
		ConnState:       &connState,
		Check: func(resp *logical.Response) error {
			if resp.Auth != nil {
				return fmt.Errorf("should not be authorized: %#v", resp)
			}
			return nil
		},
		Data: map[string]interface{}{
			"name": certName,
		},
		ErrorOk: true,
	}
}

func testAccStepListCerts(
	t *testing.T, certs []string,
) []logicaltest.TestStep {
	return []logicaltest.TestStep{
		{
			Operation: logical.ListOperation,
			Path:      "certs",
			Check: func(resp *logical.Response) error {
				if resp == nil {
					return fmt.Errorf("nil response")
				}
				if resp.Data == nil {
					return fmt.Errorf("nil data")
				}
				if resp.Data["keys"] == interface{}(nil) {
					return fmt.Errorf("nil keys")
				}
				keys := resp.Data["keys"].([]string)
				if !reflect.DeepEqual(keys, certs) {
					return fmt.Errorf("mismatch: keys is %#v, certs is %#v", keys, certs)
				}
				return nil
			},
		}, {
			Operation: logical.ListOperation,
			Path:      "certs/",
			Check: func(resp *logical.Response) error {
				if resp == nil {
					return fmt.Errorf("nil response")
				}
				if resp.Data == nil {
					return fmt.Errorf("nil data")
				}
				if resp.Data["keys"] == interface{}(nil) {
					return fmt.Errorf("nil keys")
				}
				keys := resp.Data["keys"].([]string)
				if !reflect.DeepEqual(keys, certs) {
					return fmt.Errorf("mismatch: keys is %#v, certs is %#v", keys, certs)
				}

				return nil
			},
		},
	}
}

type allowed struct {
	names                string // allowed names in the certificate, looks at common, name, dns, email [depricated]
	common_names         string // allowed common names in the certificate
	dns                  string // allowed dns names in the SAN extension of the certificate
	emails               string // allowed email names in SAN extension of the certificate
	uris                 string // allowed uris in SAN extension of the certificate
	organizational_units string // allowed OUs in the certificate
	ext                  string // required extensions in the certificate
	metadata_ext         string // allowed metadata extensions to add to identity alias
}

func testAccStepCert(t *testing.T, name string, cert []byte, policies string, testData allowed, expectError bool) logicaltest.TestStep {
	return testAccStepCertWithExtraParams(t, name, cert, policies, testData, expectError, nil)
}

func testAccStepCertWithExtraParams(t *testing.T, name string, cert []byte, policies string, testData allowed, expectError bool, extraParams map[string]interface{}) logicaltest.TestStep {
	data := map[string]interface{}{
		"certificate":                  string(cert),
		"policies":                     policies,
		"display_name":                 name,
		"allowed_names":                testData.names,
		"allowed_common_names":         testData.common_names,
		"allowed_dns_sans":             testData.dns,
		"allowed_email_sans":           testData.emails,
		"allowed_uri_sans":             testData.uris,
		"allowed_organizational_units": testData.organizational_units,
		"required_extensions":          testData.ext,
		"allowed_metadata_extensions":  testData.metadata_ext,
		"lease":                        1000,
	}
	for k, v := range extraParams {
		data[k] = v
	}
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		ErrorOk:   expectError,
		Data:      data,
		Check: func(resp *logical.Response) error {
			if resp == nil && expectError {
				return fmt.Errorf("expected error but received nil")
			}
			return nil
		},
	}
}

func testAccStepReadCertPolicy(t *testing.T, name string, expectError bool, expected map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "certs/" + name,
		ErrorOk:   expectError,
		Data:      nil,
		Check: func(resp *logical.Response) error {
			if (resp == nil || len(resp.Data) == 0) && expectError {
				return fmt.Errorf("expected error but received nil")
			}
			for key, expectedValue := range expected {
				actualValue := resp.Data[key]
				if expectedValue != actualValue {
					return fmt.Errorf("Expected to get [%v]=[%v] but read [%v]=[%v] from server for certs/%v: %v", key, expectedValue, key, actualValue, name, resp)
				}
			}
			return nil
		},
	}
}

func testAccStepCertLease(
	t *testing.T, name string, cert []byte, policies string,
) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":  string(cert),
			"policies":     policies,
			"display_name": name,
			"lease":        1000,
		},
	}
}

func testAccStepCertTTL(
	t *testing.T, name string, cert []byte, policies string,
) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":  string(cert),
			"policies":     policies,
			"display_name": name,
			"ttl":          "1000s",
		},
	}
}

func testAccStepCertMaxTTL(
	t *testing.T, name string, cert []byte, policies string,
) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":  string(cert),
			"policies":     policies,
			"display_name": name,
			"ttl":          "1000s",
			"max_ttl":      "1200s",
		},
	}
}

func testAccStepCertNoLease(
	t *testing.T, name string, cert []byte, policies string,
) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "certs/" + name,
		Data: map[string]interface{}{
			"certificate":  string(cert),
			"policies":     policies,
			"display_name": name,
		},
	}
}

func testConnState(certPath, keyPath, rootCertPath string) (tls.ConnectionState, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	// Load the CA cert required by the client to authenticate the server
	pem, err := os.ReadFile(rootCertPath)
	if err != nil {
		return tls.ConnectionState{}, fmt.Errorf("Error loading CA File: %w", err)
	}
	rootCAs := x509.NewCertPool()

	// Append the CA certificates from the PEM file to the cert pool
	ok := rootCAs.AppendCertsFromPEM(pem)
	if !ok {
		return tls.ConnectionState{}, fmt.Errorf("Error loading CA File: Couldn't parse PEM in: %s", rootCertPath)
	}

	listenConf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ClientAuth:         tls.RequestClientCert,
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}
	dialConf := listenConf.Clone()
	// start a server
	list, err := tls.Listen("tcp", "127.0.0.1:0", listenConf)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer list.Close()

	// Accept connections.
	serverErrors := make(chan error, 1)
	connState := make(chan tls.ConnectionState)
	go func() {
		defer close(connState)
		serverConn, err := list.Accept()
		serverErrors <- err
		if err != nil {
			close(serverErrors)
			return
		}
		defer serverConn.Close()

		// Read the ping
		buf := make([]byte, 4)
		_, err = serverConn.Read(buf)
		if (err != nil) && (err != io.EOF) {
			serverErrors <- err
			close(serverErrors)
			return
		} else {
			// EOF is a reasonable error condition, so swallow it.
			serverErrors <- nil
		}
		close(serverErrors)
		connState <- serverConn.(*tls.Conn).ConnectionState()
	}()

	// Establish a connection from the client side and write a few bytes.
	clientErrors := make(chan error, 1)
	go func() {
		addr := list.Addr().String()
		conn, err := tls.Dial("tcp", addr, dialConf)
		clientErrors <- err
		if err != nil {
			close(clientErrors)
			return
		}
		defer conn.Close()

		// Write ping
		_, err = conn.Write([]byte("ping"))
		clientErrors <- err
		close(clientErrors)
	}()

	for err = range clientErrors {
		if err != nil {
			return tls.ConnectionState{}, fmt.Errorf("error in client goroutine:%v", err)
		}
	}

	for err = range serverErrors {
		if err != nil {
			return tls.ConnectionState{}, fmt.Errorf("error in server goroutine:%v", err)
		}
	}
	// Grab the current state
	return <-connState, nil
}

func Test_Renew(t *testing.T) {
	storage := &logical.InmemStorage{}

	lb, err := Factory(context.Background(), &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: 300 * time.Second,
			MaxLeaseTTLVal:     1800 * time.Second,
		},
		StorageView: storage,
	})
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	b := lb.(*backend)
	connState, err := testConnState("test-fixtures/keys/cert.pem",
		"test-fixtures/keys/key.pem", "test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatalf("error testing connection state: %v", err)
	}
	ca, err := os.ReadFile("test-fixtures/root/rootcacert.pem")
	if err != nil {
		t.Fatal(err)
	}

	req := &logical.Request{
		Connection: &logical.Connection{
			ConnState: &connState,
		},
		Storage: storage,
		Auth:    &logical.Auth{},
	}

	fd := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":        "test",
			"certificate": ca,
			"policies":    "foo,bar",
		},
		Schema: pathCerts(b).Fields,
	}

	resp, err := b.pathCertWrite(context.Background(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	empty_login_fd := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: pathLogin(b).Fields,
	}
	resp, err = b.pathLogin(context.Background(), req, empty_login_fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}
	req.Auth.InternalData = resp.Auth.InternalData
	req.Auth.Metadata = resp.Auth.Metadata
	req.Auth.LeaseOptions = resp.Auth.LeaseOptions
	req.Auth.Policies = resp.Auth.Policies
	req.Auth.TokenPolicies = req.Auth.Policies
	req.Auth.Period = resp.Auth.Period

	// Normal renewal
	resp, err = b.pathLoginRenew(context.Background(), req, empty_login_fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response from renew")
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}

	// Change the policies -- this should fail
	fd.Raw["policies"] = "zip,zap"
	resp, err = b.pathCertWrite(context.Background(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = b.pathLoginRenew(context.Background(), req, empty_login_fd)
	if err == nil {
		t.Fatal("expected error")
	}

	// Put the policies back, this should be okay
	fd.Raw["policies"] = "bar,foo"
	resp, err = b.pathCertWrite(context.Background(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = b.pathLoginRenew(context.Background(), req, empty_login_fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response from renew")
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}

	// Add period value to cert entry
	period := 350 * time.Second
	fd.Raw["period"] = period.String()
	resp, err = b.pathCertWrite(context.Background(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = b.pathLoginRenew(context.Background(), req, empty_login_fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response from renew")
	}
	if resp.IsError() {
		t.Fatalf("got error: %#v", *resp)
	}

	if resp.Auth.Period != period {
		t.Fatalf("expected a period value of %s in the response, got: %s", period, resp.Auth.Period)
	}

	// Delete CA, make sure we can't renew
	resp, err = b.pathCertDelete(context.Background(), req, fd)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = b.pathLoginRenew(context.Background(), req, empty_login_fd)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("got nil response from renew")
	}
	if !resp.IsError() {
		t.Fatal("expected error")
	}
}

func TestBackend_CertUpgrade(t *testing.T) {
	s := &logical.InmemStorage{}

	config := logical.TestBackendConfig()
	config.StorageView = s

	ctx := context.Background()

	b := Backend()
	if b == nil {
		t.Fatalf("failed to create backend")
	}
	if err := b.Setup(ctx, config); err != nil {
		t.Fatal(err)
	}

	foo := &CertEntry{
		Policies:   []string{"foo"},
		Period:     time.Second,
		TTL:        time.Second,
		MaxTTL:     time.Second,
		BoundCIDRs: []*sockaddr.SockAddrMarshaler{{SockAddr: sockaddr.MustIPAddr("127.0.0.1")}},
	}

	entry, err := logical.StorageEntryJSON("cert/foo", foo)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Put(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}

	certEntry, err := b.Cert(ctx, s, "foo")
	if err != nil {
		t.Fatal(err)
	}

	exp := &CertEntry{
		Policies:   []string{"foo"},
		Period:     time.Second,
		TTL:        time.Second,
		MaxTTL:     time.Second,
		BoundCIDRs: []*sockaddr.SockAddrMarshaler{{SockAddr: sockaddr.MustIPAddr("127.0.0.1")}},
		TokenParams: tokenutil.TokenParams{
			TokenPolicies:   []string{"foo"},
			TokenPeriod:     time.Second,
			TokenTTL:        time.Second,
			TokenMaxTTL:     time.Second,
			TokenBoundCIDRs: []*sockaddr.SockAddrMarshaler{{SockAddr: sockaddr.MustIPAddr("127.0.0.1")}},
		},
	}
	if diff := deep.Equal(certEntry, exp); diff != nil {
		t.Fatal(diff)
	}
}

const (
	RegTrustedLeafCertA = `-----BEGIN CERTIFICATE-----
MIIFcTCCA1mgAwIBAgICBAAwDQYJKoZIhvcNAQELBQAwRzESMBAGA1UEChMJQ0lQ
SEVSQk9ZMRMwEQYDVQQLEwpwa2ktdG9tY2F0MRwwGgYDVQQDExNDQSBSb290IENl
cnRpZmljYXRlMCAXDTI0MDMwNDE0MDMxOVoYDzIxMjQwMzA0MTQwMzE5WjAuMRIw
EAYDVQQKEwlDSVBIRVJCT1kxGDAWBgNVBAMTD2EuY2lwaGVyYm95LmNvbTCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALy9sQmv3OBXiIJD+CYZ8UNx6Tix
AKmpXwBwvHsM/GzbIHW5DbJtCdmM2RPN6qmRRiBwc+8Sogj7Lm4h2vY0+AWOldfe
g533cMI1uAWMtJEdcrRO7V7HdHPiO0bbBX3F3ZRIqYEWlYLWWqYEPQrPv5UtbDyv
Gg7+OXqmd+qMk76+klOAZ0CCxJf/AHGdYGaBsh/+Z8dEi1L6VDSAXhmdNfSlAsZt
zZAUk0FiNQpxqZjI38MOvVYKAUGnqIkJatoqMPH+krYQxCA+HhKGepsCWfchAcFG
Fa2FoLM/+akLId5QKJ5jLLoZ0BMScjmRgp9VCmPmt5hoVvgMiOwABz5SnGpgqgLJ
uOxkOtm+VFoyD3qKH72KQZOTwU4mzqrWHIiYCThYzJwWvwmSQ4u2QNSF5pXU2Mct
sT8sJzDPu02fMGR+cZzcVSdYSJWiDgHc/IlfREeBiNO2HayPkgpiETv1UX/mNBbf
CYLJnGnYrtLyWb4tX898cfKWFt0LMdOYcKIjvc/78F45O9LD4oqKR8QTv9LkRdF6
cNfPECieBhR7gITmqMew85LmF87yscEEPUGYF7LPPz2B2Gfrs5bIuIlhiCOR7xso
xOQDGToIHw6cLdYW9aPAOkUJwBtp6TL5nrgX1EAaUutPluhHqC60JJxITTEtfqcQ
aFcvHfgRxDxUC6nPAgMBAAGjfjB8MEAGCCsGAQUFBwEBBDQwMjAwBggrBgEFBQcw
AYYkaHR0cDovL2NhLmNpcGhlcmJveS5jb206ODA4MC9jYS9vY3NwMAkGA1UdIwQC
MAAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIE
sDANBgkqhkiG9w0BAQsFAAOCAgEAj/kfWWOfvokxk0cN0vngml61uEw6HkMs2D9C
68vuH3L+EBnU+RjUngVbeZ08H/dxQHwymW25CwdnfAXMn7PzSrUwjD1Qd/K0mWFg
CexGKpXnepyo2mL3ZEzRfdQ87DCfyIX6C1SVlGkU5/kLYd20nbJaqNe1OVHj1Vrr
aZpdbO2v2gMhbUP4EqEtfFNa41jnSZE845nE+2N/avbfLlq//v4FwU1JZVdeyP1Q
o4rGNaGpWLveRrtqhNLEyq35gN4uRElE0SxYuYzXInfJC5h1gB1yBtvi7Wson8S8
Hn/Sf95SBHJwSPs49WwWBtIaQyfvqnYrjX2mwp/TCbUuhIB8edlOWD8BTZ7+AKFH
7qji8Qj+rHauEMryR30x6wqrSQyh30Xv0azaVIpK/kT/XsvRCowgCRhgaejHAN5a
zKtj41B6VfVCRxGYC5wr8tWOWpJysBej1OtmQwEP7XhZFQh/ME3OPwqXXAXOUUnv
0Up84wvWFHBkDPJeTSiS2qefZk/HDeEL5xgFp0A4PLjrSO43KTc6nyPxl5+xFJ7b
/zY+XAR1YD5SzsgI7rkdx538u89vR+sKKJ+XPAJUa5JhPQjTVL9Exr3cqc5kazwT
Rp+Yy6n6wYsGA9916PqKVfC3dqSbNyO5Gdw8V5bMdp/E0j9f+D6sgsJFFFVKCB2t
arXtCcc=
-----END CERTIFICATE-----
`
	RegTrustedLeafKeyA = `-----BEGIN PRIVATE KEY-----
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
Qy9lVAuKDEh15921mPxb074a6ByNMg==
-----END PRIVATE KEY-----
`
	RegTrustedLeafCertB = `-----BEGIN CERTIFICATE-----
MIIFcDCCA1igAwIBAgICBAAwDQYJKoZIhvcNAQELBQAwRjESMBAGA1UEChMJQ0lQ
SEVSQk9ZMRMwEQYDVQQLEwpwa2ktdG9tY2F0MRswGQYDVQQDExJDQSBTdWIgQ2Vy
dGlmaWNhdGUwIBcNMjQwMzA0MTQwMzIwWhgPMjEyNDAzMDQxNDAzMjBaMC4xEjAQ
BgNVBAoTCUNJUEhFUkJPWTEYMBYGA1UEAxMPYi5jaXBoZXJib3kuY29tMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAztMFwBX8R7lsWz9WpFtEK5ZXXBjk
IZ5GkdY9gPXRyKPdBj0gckjNOWy74xJ+TYxT2+EPPDwe4KD7IGDM0PG9JGATzG9O
OQ7kJuNycG4zFu+BSzMGcfRc1y88j/GBubfy2R4tNpUb4KJ4C8JaWo2BIjjmywJS
ywq4CwaDUVgJOGIr57y2iljCuCVGfTpB6g5AHlJ6eMX6Yl254dHmcUA9JlP49C5H
XmJbAB9vn4EHEBN8zIjWLUIckwAxKjDdfjrwNfheHSGVs+uP8u8PC09pAs7y6jnT
3QEwqg9wIoK4L4bxy4Gj0D4ZxDpEgYlZNIFRcHrabm+IjKSy2eB01Vpkc2tgZmfs
uYEzuxg/HfujosJYrfeYD3lZGU8xnoJzE0MXbfGCEQLyCm3XShqNIh/D4st/gptJ
5IxknNfIKtQ8n5KIbVvCasPxyy0hHN6NE2Z4pzA59JoWQa8gBC7pHCJ/kLLbgLf1
5dHwJcf444oh54hddQOgzhVxiMxwcJDEh/jKiqAYw4cF559QYBlrHx3U8VMJNi0M
ai9jWVsz7/KRrjuO1bvV/M6BrAVfmeywrmcFaZF6r3q5JThdPoao24ba9j5m8brx
F1vN2tSxml/xNCNrgdjPUTw8rBexoCmt9NRF4SGZyhL3EjYSNvECncqRRTIkdgP+
x0FEbsI7NxrpMokCAwEAAaN+MHwwQAYIKwYBBQUHAQEENDAyMDAGCCsGAQUFBzAB
hiRodHRwOi8vY2EuY2lwaGVyYm95LmNvbTo4MDgwL2NhL29jc3AwCQYDVR0jBAIw
ADAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgSw
MA0GCSqGSIb3DQEBCwUAA4ICAQC7JJ3kIB0hW5wRTUZKKWL2cfJ3To7YStXh78P3
h2nby4cD6UbPkQW9Yn3Av0sMqBHr6Pk3mHKL+3sE895/PyGMTqQbLyVDMi4HOd2i
sUf3snhNjRRRvM7IeHNhjvI004XKlGIqo9rfn3CFnWo663za3He8jsc4i+hxTnya
KaW8D8gJkTJRW3fg1ACsESEG4ITY83PkERrzBJvPLcza75tjtrPUrHy4qEwVnQcD
XWZN0Y6pTD4M4mtBXfaoKKeujxf+kT/XvnPgAR1OL0vs3ttotZSAQe35hn5hlNX3
Aa4ZzxIhNGihyNHPKD1I/F3izCkUeDHtk/aLAgv9F7CfJux80cbnkzAqE0S/bdbR
PQlPKDp0REy6nOXbJ35R5Agadn6i4r8fFDKzR8aGylymGcsF4YOlowo+PaS51SFc
lBOM/sQdZVs3K7HEIzUkAudwVE2/sj5cZlNykW741LkB+Ezk2QMAVwkyCsaC9Tu/
GTdMC0+AtueG9NvJ7fv36hBeXAFuS728K5mPPtzhCmmHcplNaf23NiTob++sb96k
EJy3f0IRpQji0cgIfrqcgbm4BNwepGAq46c+gyGWD7HOTaNVe0hNOgmBAZRDfIJ8
Mt/hEsvQYDL/Y4OSv+fQD/KVy9nx7zbXPMqcko+9w+TT/2AVfqX2uRo3DPoVwJy7
mLG5gA==
-----END CERTIFICATE-----
`
	RegTrustedLeafKeyB = `-----BEGIN PRIVATE KEY-----
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
mr2dJsMn54TXDOZYRQd5WVKDDu8xoJI=
-----END PRIVATE KEY-----
`
)

func TestBackend_RegressionDifferentTrustedLeaf(t *testing.T) {
	// Cert auth method
	coreConfig := &vault.CoreConfig{
		DisableCache: true,
		Logger:       log.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{
			"cert": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()
	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	var err error

	// Enable the cert auth method
	err = client.Sys().EnableAuthWithOptions("cert", &api.EnableAuthOptions{
		Type: "cert",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Set the first leaf cert as a trusted certificate in the backend
	_, err = client.Logical().Write("auth/cert/certs/trusted-leaf", map[string]interface{}{
		"display_name": "trusted-cert",
		"policies":     "default",
		"certificate":  RegTrustedLeafCertA,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create temporary files for CA cert, client cert and client cert key.
	// This is used to configure TLS in the api client.
	caCertFile, err := os.CreateTemp("", "caCert")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(caCertFile.Name())
	if _, err := caCertFile.Write([]byte(cluster.CACertPEM)); err != nil {
		t.Fatal(err)
	}
	if err := caCertFile.Close(); err != nil {
		t.Fatal(err)
	}

	leafCertAFile, err := os.CreateTemp("", "leafCertA")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(leafCertAFile.Name())
	if _, err := leafCertAFile.Write([]byte(RegTrustedLeafCertA)); err != nil {
		t.Fatal(err)
	}
	if err := leafCertAFile.Close(); err != nil {
		t.Fatal(err)
	}

	leafCertAKeyFile, err := os.CreateTemp("", "leafCertAKey")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(leafCertAKeyFile.Name())
	if _, err := leafCertAKeyFile.Write([]byte(RegTrustedLeafKeyA)); err != nil {
		t.Fatal(err)
	}
	if err := leafCertAKeyFile.Close(); err != nil {
		t.Fatal(err)
	}

	leafCertBFile, err := os.CreateTemp("", "leafCertB")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(leafCertBFile.Name())
	if _, err := leafCertBFile.Write([]byte(RegTrustedLeafCertB)); err != nil {
		t.Fatal(err)
	}
	if err := leafCertBFile.Close(); err != nil {
		t.Fatal(err)
	}

	leafCertBKeyFile, err := os.CreateTemp("", "leafCertBKey")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(leafCertBKeyFile.Name())
	if _, err := leafCertBKeyFile.Write([]byte(RegTrustedLeafKeyB)); err != nil {
		t.Fatal(err)
	}
	if err := leafCertBKeyFile.Close(); err != nil {
		t.Fatal(err)
	}

	// This function is a copy-pasta from the NewTestCluster, with the
	// modification to reconfigure the TLS on the api client with the leaf
	// certificate generated above.
	getAPIClient := func(port int, tlsConfig *tls.Config, leafCert string, leafKey string) *api.Client {
		transport := cleanhttp.DefaultPooledTransport()
		transport.TLSClientConfig = tlsConfig.Clone()
		if err := http2.ConfigureTransport(transport); err != nil {
			t.Fatal(err)
		}
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// This can of course be overridden per-test by using its own client
				return fmt.Errorf("redirects not allowed in these tests")
			},
		}
		config := api.DefaultConfig()
		if config.Error != nil {
			t.Fatal(config.Error)
		}
		config.Address = fmt.Sprintf("https://127.0.0.1:%d", port)
		config.HttpClient = client

		// Set the above issued certificates as the client certificates
		config.ConfigureTLS(&api.TLSConfig{
			CACert:     caCertFile.Name(),
			ClientCert: leafCert,
			ClientKey:  leafKey,
		})

		apiClient, err := api.NewClient(config)
		if err != nil {
			t.Fatal(err)
		}
		return apiClient
	}

	// Create a new api client with the incorrect leaf; it should fail.
	newBClient := getAPIClient(cores[0].Listeners[0].Address.Port, cores[0].TLSConfig(), leafCertBFile.Name(), leafCertBKeyFile.Name())

	secret, err := newBClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": "trusted-leaf",
	})
	if err == nil {
		t.Fatalf("when logging in with different leaf from trusted, expected err but got none: err=%v / secret=%v", err, secret)
	}
	if secret != nil {
		t.Fatalf("when logging in with different leaf from trusted, expected empty secret but got %v", secret)
	}

	// Create a new API client with the correct leaf; it should succeed.
	newAClient := getAPIClient(cores[0].Listeners[0].Address.Port, cores[0].TLSConfig(), leafCertAFile.Name(), leafCertAKeyFile.Name())

	secret, err = newAClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": "trusted-leaf",
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Fatalf("expected a successful authentication")
	}
}
