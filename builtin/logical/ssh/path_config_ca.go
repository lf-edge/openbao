// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"golang.org/x/crypto/ssh"

	"github.com/mikesmitty/edkey"
)

type keyStorageEntry struct {
	Key string `json:"key" structs:"key" mapstructure:"key"`
}

func pathConfigCA(b *backend) *framework.Path {
	fields := map[string]*framework.FieldSchema{}
	fields = addSubmitIssuerCommonFields(fields)

	return &framework.Path{
		Pattern: "config/ca",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
		},

		Fields: fields,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigCAUpdate,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "default-ca",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields:      issuerOKResponseFields,
					}},
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigCADelete,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "ca",
					OperationVerb:   "purge",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
					}},
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigCARead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "read",
					OperationSuffix: "default-ca",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields:      issuerOKResponseFields,
					}},
				},
			},
		},

		HelpSynopsis:    pathConfigCASyn,
		HelpDescription: pathConfigCADesc,
	}
}

func (b *backend) pathConfigCARead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	issuer, err := sc.fetchDefaultIssuer()
	if err != nil {
		return handleStorageContextErr(err)
	}

	return respondReadIssuer(issuer)
}

func (b *backend) pathConfigCADelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Since we're planning on updating issuers here, grab the lock so we've
	// got a consistent view.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	// Use the transaction storage if there's one.
	if txnStorage, ok := req.Storage.(logical.TransactionalStorage); ok {
		txn, err := txnStorage.BeginTx(ctx)
		if err != nil {
			return nil, err
		}

		defer txn.Rollback(ctx)
		req.Storage = txn
	}

	sc := b.makeStorageContext(ctx, req.Storage)

	issuersDeleted, err := sc.purgeIssuers()
	if err != nil {
		return handleStorageContextErr(err, "failed to delete issuers")
	}

	// Commit our transaction if we created one!
	if txn, ok := req.Storage.(logical.Transaction); ok {
		if err := txn.Commit(ctx); err != nil {
			return nil, err
		}
	}

	response := &logical.Response{}

	if issuersDeleted > 0 {
		response.AddWarning(fmt.Sprintf("Deleted %d issuers, including the configured 'default'.", issuersDeleted))
	}

	return response, nil
}

func caKey(ctx context.Context, storage logical.Storage, keyType string) (*keyStorageEntry, error) {
	var path, deprecatedPath string
	switch keyType {
	case caPrivateKey:
		path = caPrivateKeyStoragePath
		deprecatedPath = caPrivateKeyStoragePathDeprecated
	case caPublicKey:
		path = caPublicKeyStoragePath
		deprecatedPath = caPublicKeyStoragePathDeprecated
	default:
		return nil, fmt.Errorf("unrecognized key type %q", keyType)
	}

	entry, err := storage.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key of type %q: %w", keyType, err)
	}

	if entry == nil {
		// If the entry is not found, look at an older path. If found, upgrade
		// it.
		entry, err = storage.Get(ctx, deprecatedPath)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			entry, err = logical.StorageEntryJSON(path, keyStorageEntry{
				Key: string(entry.Value),
			})
			if err != nil {
				return nil, err
			}
			if err := storage.Put(ctx, entry); err != nil {
				return nil, err
			}
			if err = storage.Delete(ctx, deprecatedPath); err != nil {
				return nil, err
			}
		}
	}
	if entry == nil {
		return nil, nil
	}

	var keyEntry keyStorageEntry
	if err := entry.DecodeJSON(&keyEntry); err != nil {
		return nil, err
	}

	return &keyEntry, nil
}

func (b *backend) pathConfigCAUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Since we're planning on updating issuers here, grab the lock so we've
	// got a consistent view.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	publicKey, privateKey, err := b.keys(data)
	if err != nil {
		return handleStorageContextErr(err)
	}

	// Use the transaction storage if there's one.
	if txnStorage, ok := req.Storage.(logical.TransactionalStorage); ok {
		txn, err := txnStorage.BeginTx(ctx)
		if err != nil {
			return nil, err
		}

		defer txn.Rollback(ctx)
		req.Storage = txn
	}

	sc := b.makeStorageContext(ctx, req.Storage)

	// Create a new issuer entry
	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("error generating issuer's unique identifier: %w", err)
	}
	name, err := getIssuerName(sc, data)
	if err != nil && err != errIssuerNameIsEmpty {
		return handleStorageContextErr(err)
	}
	issuer := &issuerEntry{
		ID:         id,
		Name:       name,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Version:    1,
	}

	err = sc.writeIssuer(issuer)
	if err != nil {
		return handleStorageContextErr(err, "failed to persist the issuer")
	}

	response, err := respondReadIssuer(issuer)

	// Update issuers config to set new issuers as the 'default'
	err = sc.setIssuersConfig(&issuerConfigEntry{DefaultIssuerID: id})
	if err != nil {
		// It is not possible to have this error in the transaction, so check
		// storage type and skip if is a transaction
		if _, ok := req.Storage.(logical.Transaction); !ok {
			// Even if the new issuer fails to be set as default, we want to return
			// the newly submitted issuer with a warning
			response.AddWarning(fmt.Sprintf("Unable to update default issuers configuration: %s", err.Error()))
		}
	}

	// Commit our transaction if we created one!
	if txn, ok := req.Storage.(logical.Transaction); ok {
		if err := txn.Commit(ctx); err != nil {
			return nil, err
		}
	}

	return response, nil
}

func generateSSHKeyPair(randomSource io.Reader, keyType string, keyBits int) (string, string, error) {
	if randomSource == nil {
		randomSource = rand.Reader
	}

	var publicKey crypto.PublicKey
	var privateBlock *pem.Block

	switch keyType {
	case ssh.KeyAlgoRSA, "rsa":
		if keyBits == 0 {
			keyBits = 4096
		}

		if keyBits < 2048 {
			return "", "", fmt.Errorf("refusing to generate weak %v key: %v bits < 2048 bits", keyType, keyBits)
		}

		privateSeed, err := rsa.GenerateKey(randomSource, keyBits)
		if err != nil {
			return "", "", err
		}

		privateBlock = &pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: nil,
			Bytes:   x509.MarshalPKCS1PrivateKey(privateSeed),
		}

		publicKey = privateSeed.Public()
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, "ec":
		var curve elliptic.Curve
		switch keyType {
		case ssh.KeyAlgoECDSA256:
			curve = elliptic.P256()
		case ssh.KeyAlgoECDSA384:
			curve = elliptic.P384()
		case ssh.KeyAlgoECDSA521:
			curve = elliptic.P521()
		default:
			switch keyBits {
			case 0, 256:
				curve = elliptic.P256()
			case 384:
				curve = elliptic.P384()
			case 521:
				curve = elliptic.P521()
			default:
				return "", "", fmt.Errorf("unknown ECDSA key pair algorithm and bits: %v / %v", keyType, keyBits)
			}
		}

		privateSeed, err := ecdsa.GenerateKey(curve, randomSource)
		if err != nil {
			return "", "", err
		}

		marshalled, err := x509.MarshalECPrivateKey(privateSeed)
		if err != nil {
			return "", "", err
		}

		privateBlock = &pem.Block{
			Type:    "EC PRIVATE KEY",
			Headers: nil,
			Bytes:   marshalled,
		}

		publicKey = privateSeed.Public()
	case ssh.KeyAlgoED25519, "ed25519":
		_, privateSeed, err := ed25519.GenerateKey(randomSource)
		if err != nil {
			return "", "", err
		}

		marshalled := edkey.MarshalED25519PrivateKey(privateSeed)
		if marshalled == nil {
			return "", "", errors.New("unable to marshal ed25519 private key")
		}

		privateBlock = &pem.Block{
			Type:    "OPENSSH PRIVATE KEY",
			Headers: nil,
			Bytes:   marshalled,
		}

		publicKey = privateSeed.Public()
	default:
		return "", "", fmt.Errorf("unknown ssh key pair algorithm: %v", keyType)
	}

	public, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}

	return string(ssh.MarshalAuthorizedKey(public)), string(pem.EncodeToMemory(privateBlock)), nil
}

var (
	pathConfigCASyn  = `Configure the default SSH issuer used for signing and verification operations.`
	pathConfigCADesc = `
This endpoint allows configuring the default SSH issuer used for signing and verification operations.
If a 'default' issuer has already been set, this endpoint will override it.

The delete operation will remove all issuers, including the 'default' one. This operation is not reversible.

The read operation will return the 'default' issuer information.
`
)
