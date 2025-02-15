package ssh

import (
	"context"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func Test_migrateStorageEmptyStorage(t *testing.T) {
	t.Parallel()
	startTime := time.Now()
	ctx := context.Background()
	b, s := CreateBackendWithStorage(t)
	sc := b.makeStorageContext(ctx, s)

	// Fetch migration log
	info, err := getMigrationInfo(ctx, s)
	require.Nil(t, info)
	require.NoError(t, err)

	request := &logical.InitializationRequest{Storage: s}
	err = b.initialize(ctx, request)
	require.NoError(t, err)

	// Fetch migration log again
	info, err = getMigrationInfo(ctx, s)
	require.Equal(t, latestMigrationVersion, info.MigrationVersion)
	require.True(t, startTime.Before(info.Created),
		"created migration info entry time (%v) was before our start time(%v)?", info.Created, startTime)

	// Validate that there are no issuers configured before
	issuerIds, err := sc.listIssuers()
	require.NoError(t, err)
	require.Equal(t, 0, len(issuerIds))
}

func Test_migrateStorage(t *testing.T) {
	t.Parallel()
	startTime := time.Now()
	ctx := context.Background()
	b, s := CreateBackendWithStorage(t)
	sc := b.makeStorageContext(ctx, s)

	// Fetch migration log
	info, err := getMigrationInfo(ctx, s)
	require.Nil(t, info)
	require.NoError(t, err)

	// Set CA public key
	json, err := logical.StorageEntryJSON(caPublicKeyStoragePath, &keyStorageEntry{
		Key: testCAPublicKey,
	})
	require.NoError(t, err)
	err = s.Put(ctx, json)
	require.NoError(t, err)

	// Set CA private key
	json, err = logical.StorageEntryJSON(caPrivateKeyStoragePath, &keyStorageEntry{
		Key: testCAPrivateKey,
	})
	require.NoError(t, err)
	err = s.Put(ctx, json)
	require.NoError(t, err)

	// Validate that there were no issuers configured before
	issuerIds, err := sc.listIssuers()
	require.NoError(t, err)
	require.Equal(t, 0, len(issuerIds))

	request := &logical.InitializationRequest{Storage: s}
	err = b.initialize(ctx, request)
	require.NoError(t, err)

	// Fetch migration log again
	info, err = getMigrationInfo(ctx, s)
	require.NotNil(t, info)
	require.NoError(t, err)
	require.Equal(t, latestMigrationVersion, info.MigrationVersion)
	require.True(t, startTime.Before(info.Created),
		"created migration info entry time (%v) was before our start time(%v)?", info.Created, startTime)

	// Verify issuers has been created
	issuerIds, err = sc.listIssuers()
	require.Equal(t, 1, len(issuerIds))
	require.NoError(t, err)
	issuerId := issuerIds[0]

	// Verify that issuer has been set as default
	entry, err := sc.fetchDefaultIssuer()
	require.NotNil(t, entry)
	require.NoError(t, err)
	require.Equal(t, issuerId, entry.ID)

	// Make sure if we attempt to re-run the migration nothing happens...
	err = migrateStorage(ctx, b, s)
	require.NoError(t, err)
}
