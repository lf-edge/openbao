// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/salt"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const operationPrefixSSH = "ssh"

type backend struct {
	*framework.Backend
	view      logical.Storage
	salt      *salt.Salt
	saltMutex sync.RWMutex
	// Write lock around issuers
	issuersLock sync.Mutex
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend(conf *logical.BackendConfig) (*backend, error) {
	var b backend
	b.view = conf.StorageView
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"verify",
				"public_key",
				"issuer/+/public_key",
			},

			LocalStorage: []string{
				"otp/",
			},

			SealWrapStorage: []string{
				caPrivateKey,
				caPrivateKeyStoragePath,
				keysStoragePrefix,
				issuerPrefix,
				storageIssuerConfig,
			},
		},

		Paths: []*framework.Path{
			pathConfigZeroAddress(&b),
			pathListRoles(&b),
			pathRoles(&b),
			pathCredsCreate(&b),
			pathLookup(&b),
			pathVerify(&b),
			pathConfigCA(&b),
			pathSign(&b),
			pathIssue(&b),
			pathFetchPublicKey(&b),
			pathCleanupKeys(&b),
			pathConfigIssuers(&b),
			// Issuer APIs
			pathIssuers(&b),
			pathSubmitIssuer(&b),
			pathListIssuers(&b),
			pathGetIssuerPublicKeyUnauthenticated(&b),
		},

		Secrets: []*framework.Secret{
			secretOTP(&b),
		},

		Invalidate:     b.invalidate,
		BackendType:    logical.TypeLogical,
		InitializeFunc: b.initialize,
	}
	return &b, nil
}

func (b *backend) Salt(ctx context.Context) (*salt.Salt, error) {
	b.saltMutex.RLock()
	if b.salt != nil {
		defer b.saltMutex.RUnlock()
		return b.salt, nil
	}
	b.saltMutex.RUnlock()
	b.saltMutex.Lock()
	defer b.saltMutex.Unlock()
	if b.salt != nil {
		return b.salt, nil
	}
	salt, err := salt.NewSalt(ctx, b.view, &salt.Config{
		HashFunc: salt.SHA256Hash,
		Location: salt.DefaultLocation,
	})
	if err != nil {
		return nil, err
	}
	b.salt = salt
	return salt, nil
}

func (b *backend) invalidate(_ context.Context, key string) {
	switch key {
	case salt.DefaultLocation:
		b.saltMutex.Lock()
		defer b.saltMutex.Unlock()
		b.salt = nil
	}
}

const backendHelp = `
The SSH backend generates credentials allowing clients to establish SSH
connections to remote hosts.

There are two variants of the backend, which generate different types of
credentials: One-Time Passwords (OTPs) and certificate authority. The desired behavior
is role-specific and chosen at role creation time with the 'key_type'
parameter.

Please see the backend documentation for a thorough description of both
types. The OpenBao team strongly recommends the OTP type.

After mounting this backend, before generating credentials, configure the
backend's lease behavior using the 'config/lease' endpoint and create roles
using the 'roles/' endpoint.
`

// initialize is used to peform a possible SSH storage migration if needed
func (b *backend) initialize(ctx context.Context, _ *logical.InitializationRequest) error {
	err := b.initializeIssuersStorage(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (b *backend) initializeIssuersStorage(ctx context.Context) error {
	// Grab the lock prior to the updating of the storage lock preventing us flipping
	// the storage flag midway through the request stream of other requests.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	// Use the transaction storage if there's one.
	storage := b.view
	if txnStorage, ok := b.view.(logical.TransactionalStorage); ok {
		txn, err := txnStorage.BeginTx(ctx)
		if err != nil {
			return err
		}

		defer txn.Rollback(ctx)
		storage = txn
	}

	// Early exit if not a primary cluster or performance secondary with a local mount.
	if b.System().ReplicationState().HasState(consts.ReplicationDRSecondary|consts.ReplicationPerformanceStandby) ||
		(!b.System().LocalMount() && b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary)) {
		b.Logger().Debug("skipping SSH migration as we are not on primary or secondary with a local mount")
		return nil
	}

	if err := migrateStorage(ctx, b, storage); err != nil {
		return err
	}

	// Commit our transaction if we created one!
	if txn, ok := storage.(logical.Transaction); ok {
		if err := txn.Commit(ctx); err != nil {
			return err
		}
	}

	return nil
}
