package ssh

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// This allows us to record the version of the migration code within the log entry
const (
	latestMigrationVersion = 1
)

type migrationInfo struct {
	Created          time.Time `json:"created"`
	MigrationVersion int       `json:"migrationVersion"`
}

func getMigrationInfo(ctx context.Context, s logical.Storage) (*migrationInfo, error) {
	entry, err := s.Get(ctx, MigrationInfoKey)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	info := &migrationInfo{}
	if err := entry.DecodeJSON(info); err != nil {
		return nil, err
	}

	return info, nil
}

func putMigrationInfo(ctx context.Context, s logical.Storage, info *migrationInfo) error {
	entry, err := logical.StorageEntryJSON(MigrationInfoKey, info)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func migrateStorage(ctx context.Context, b *backend, s logical.Storage) error {
	info, err := getMigrationInfo(ctx, s)
	if err != nil {
		return err
	}

	if info != nil && info.MigrationVersion == latestMigrationVersion {
		// Already migrated
		return nil
	}

	// Perform migration
	b.Logger().Info("Performing SSH migration to new issuers layout")
	info = &migrationInfo{
		MigrationVersion: latestMigrationVersion,
		Created:          time.Now(),
	}
	defer putMigrationInfo(ctx, s, info)

	publicKeyCaEntry, err := caKey(ctx, s, caPublicKey)
	if err != nil {
		return err
	}

	if publicKeyCaEntry == nil {
		return nil
	}

	privateKeyCaEntry, err := caKey(ctx, s, caPublicKey)
	if err != nil {
		return err
	}

	if privateKeyCaEntry == nil {
		return nil
	}

	// If we haven't returned by now, we have a valid CA keypair to be migrated
	sc := b.makeStorageContext(ctx, s)

	// Create a new issuer entry
	id, err := uuid.GenerateUUID()
	if err != nil {
		return err
	}
	issuer := &issuerEntry{
		ID:         id,
		PublicKey:  publicKeyCaEntry.Key,
		PrivateKey: privateKeyCaEntry.Key,
		Version:    1,
	}

	err = sc.writeIssuer(issuer)
	if err != nil {
		return err
	}

	// Set the default issuer
	err = sc.setIssuersConfig(&issuerConfigEntry{DefaultIssuerID: id})
	if err != nil {
		return err
	}
	b.Logger().Info(fmt.Sprintf("Migration generated the issuer (%s) and set it as default", id))

	return nil
}
