// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	defaultRef = "default"

	MigrationInfoKey    = "config/migrationInfo"
	issuerPrefix        = "config/issuer/"
	storageIssuerConfig = "config/issuers"

	caPublicKey                       = "ca_public_key"
	caPrivateKey                      = "ca_private_key"
	caPublicKeyStoragePath            = "config/ca_public_key"
	caPublicKeyStoragePathDeprecated  = "public_key"
	caPrivateKeyStoragePath           = "config/ca_private_key"
	caPrivateKeyStoragePathDeprecated = "config/ca_bundle"

	maxRolesToScanOnIssuerChange = 100
	maxRolesToFindOnIssuerChange = 10

	// Used as a quick sanity check for a reference id lookups...
	uuidLength = 36
)

const (
	IssuerRefNotFound = "not-found"
)

type issuerEntry struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	Version    uint   `json:"version"`
}

type issuerConfigEntry struct {
	DefaultIssuerID string `json:"default"`
}

type storageContext struct {
	Context context.Context
	Storage logical.Storage
	Backend *backend
}

// makeStorageContext creates a storage context with the given context and storage
func (b *backend) makeStorageContext(ctx context.Context, s logical.Storage) *storageContext {
	return &storageContext{
		Context: ctx,
		Storage: s,
		Backend: b,
	}
}

// writeIssuer writes an issuerEntry to storage
func (sc *storageContext) writeIssuer(issuer *issuerEntry) error {
	issuerId := issuer.ID

	json, err := logical.StorageEntryJSON(issuerPrefix+issuerId, issuer)
	if err != nil {
		return err
	}

	return sc.Storage.Put(sc.Context, json)
}

// deleteIssuer removes an issuer from storage and unsets from default, if was.
// Returns a boolean indicating if the issuer was the default issuer
func (sc *storageContext) deleteIssuer(id string) (bool, error) {
	config, err := sc.getIssuersConfig()
	if err != nil {
		return false, err
	}

	wasDefault := false
	if config.DefaultIssuerID == id {
		wasDefault = true
		config.DefaultIssuerID = ""
		if err := sc.setIssuersConfig(config); err != nil {
			return wasDefault, err
		}
	}

	return wasDefault, sc.Storage.Delete(sc.Context, issuerPrefix+id)
}

// setIssuersConfig writes the issuers configuration to storage
func (sc *storageContext) setIssuersConfig(config *issuerConfigEntry) error {
	json, err := logical.StorageEntryJSON(storageIssuerConfig, config)
	if err != nil {
		return err
	}

	if err := sc.Storage.Put(sc.Context, json); err != nil {
		return err
	}

	return nil
}

// getIssuersConfig fetches the issuers configuration from storage
func (sc *storageContext) getIssuersConfig() (*issuerConfigEntry, error) {
	entry, err := sc.Storage.Get(sc.Context, storageIssuerConfig)
	if err != nil {
		return nil, err
	}

	issuerConfig := &issuerConfigEntry{}
	if entry != nil {
		if err := entry.DecodeJSON(issuerConfig); err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode issuer configuration: %v", err)}
		}
	}

	return issuerConfig, nil
}

// listIssuers returns a list of all issuer identifiers
func (sc *storageContext) listIssuers() ([]string, error) {
	return sc.listIssuersPage("", -1)
}

// listIssuersPage returns a list of issuer identifiers starting after the given identifier
func (sc *storageContext) listIssuersPage(after string, limit int) ([]string, error) {
	strList, err := sc.Storage.ListPage(sc.Context, issuerPrefix, after, limit)
	if err != nil {
		return nil, err
	}

	issuerIds := make([]string, 0, len(strList))
	for _, entry := range strList {
		issuerIds = append(issuerIds, entry)
	}

	return issuerIds, nil
}

// fetchIssuerById returns an issuer entry based on issuerId, if none found an error is returned.
func (sc *storageContext) fetchIssuerById(issuerId string) (*issuerEntry, error) {
	if len(issuerId) == 0 {
		return nil, errutil.InternalError{Err: "unable to fetch ssh issuer: empty issuer identifier"}
	}

	entry, err := sc.Storage.Get(sc.Context, issuerPrefix+issuerId)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch ssh issuer: %v", err)}
	}
	if entry == nil {
		return nil, errutil.UserError{Err: fmt.Sprintf("ssh issuer id '%s' does not exist", issuerId)}
	}

	var issuer issuerEntry
	if err := entry.DecodeJSON(&issuer); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode ssh issuer with id %s: %v", issuerId, err)}
	}

	return &issuer, nil
}

// Lookup within storage the value of reference, assuming the string is a
// reference to an issuer entry, returning the id or an error if not found.
func (sc *storageContext) resolveIssuerReference(ref string) (string, error) {
	if ref == defaultRef {
		// If reference is 'default', fetch the default issuer ID from the configuration
		issuerConfig, err := sc.getIssuersConfig()
		if err != nil {
			return "", err
		}
		if len(issuerConfig.DefaultIssuerID) == 0 {
			return IssuerRefNotFound, errutil.UserError{Err: "no default issuer currently configured"}
		}

		return issuerConfig.DefaultIssuerID, nil
	}

	// Look by a direct get first to see if our reference is an ID, if so, return it
	if len(ref) == uuidLength {
		entry, err := sc.Storage.Get(sc.Context, issuerPrefix+ref)
		if err != nil {
			return "", err
		}
		if entry != nil {
			return ref, nil
		}
	}

	// If not, pull all issuers from storage
	issuers, err := sc.listIssuers()
	if err != nil {
		return "", err
	}

	// Iterate through all issuers and return the ID of the issuer with the matching name
	for _, id := range issuers {
		issuer, err := sc.fetchIssuerById(id)
		if err != nil {
			return "", err
		}

		if issuer.Name == ref {
			return issuer.ID, nil
		}
	}

	// If the reference is not an ID or a name, return an error
	return IssuerRefNotFound, errutil.UserError{Err: fmt.Sprintf("unable to find issuer for reference: %v", ref)}
}

// fetchDefaultIssuer fetches the default issuer if set, otherwise nil is returned
func (sc *storageContext) fetchDefaultIssuer() (*issuerEntry, error) {
	config, err := sc.getIssuersConfig()
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch the issuer's config: %s", err)}
	}

	if len(config.DefaultIssuerID) == 0 {
		return nil, errutil.UserError{Err: "no default issuer currently configured"}
	}

	issuer, err := sc.fetchIssuerById(config.DefaultIssuerID)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch the default issuer: %s", err)}
	}

	return issuer, nil
}

// purgeIssuers fetches all issuer identifiers and deletes them from storage.
// Returns the number of issuers deleted and an error if any.
func (sc *storageContext) purgeIssuers() (int, error) {
	var deleted int
	issuerIds, err := sc.listIssuers()
	if err != nil {
		return deleted, err
	}

	for _, id := range issuerIds {
		if _, err := sc.deleteIssuer(id); err != nil {
			return deleted, err
		}
		deleted += 1
	}

	return deleted, nil
}

// checkForRolesReferencingIssuer checks if any roles are referencing the given issuer. The reference can either be the issuer's ID or name.
func (sc *storageContext) checkForRolesReferencingIssuer(issuerName string) (timeout bool, inUseBy int32, err error) {
	roleEntries, err := sc.Storage.List(sc.Context, "roles/")
	if err != nil {
		return false, 0, err
	}

	inUseBy = 0
	checkedRoles := 0

	for _, roleName := range roleEntries {
		entry, err := sc.Storage.Get(sc.Context, "roles/"+roleName)
		if err != nil {
			return false, inUseBy, err
		}

		if entry != nil { // If nil, someone deleted an entry since we haven't taken a lock here so just continue
			var role sshRole
			err = entry.DecodeJSON(&role)
			if err != nil {
				return false, inUseBy, err
			}
			if role.Issuer == issuerName {
				inUseBy = inUseBy + 1
				if inUseBy >= maxRolesToFindOnIssuerChange {
					return true, inUseBy, nil
				}
			}
		}
		checkedRoles = checkedRoles + 1
		if checkedRoles >= maxRolesToScanOnIssuerChange {
			return true, inUseBy, nil
		}
	}

	return false, inUseBy, nil
}
