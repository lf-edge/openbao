// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package approle

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/helper/parseip"
	"github.com/openbao/openbao/sdk/v2/helper/cidrutil"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// secretIDStorageEntry represents the information stored in storage
// when a SecretID is created. The structure of the SecretID storage
// entry is the same for all the types of SecretIDs generated.
type secretIDStorageEntry struct {
	// Accessor for the SecretID. It is a random UUID serving as
	// a secondary index for the SecretID. This uniquely identifies
	// the SecretID it belongs to, and hence can be used for listing
	// and deleting SecretIDs. Accessors cannot be used as valid
	// SecretIDs during login.
	SecretIDAccessor string `json:"secret_id_accessor" mapstructure:"secret_id_accessor"`

	// Number of times this SecretID can be used to perform the login
	// operation
	SecretIDNumUses int `json:"secret_id_num_uses" mapstructure:"secret_id_num_uses"`

	// Duration after which this SecretID should expire. This is capped by
	// the backend mount's max TTL value.
	SecretIDTTL time.Duration `json:"secret_id_ttl" mapstructure:"secret_id_ttl"`

	// The time when the SecretID was created
	CreationTime time.Time `json:"creation_time" mapstructure:"creation_time"`

	// The time when the SecretID becomes eligible for tidy operation.
	// Tidying is performed by the PeriodicFunc of the backend which is 1
	// minute apart.
	ExpirationTime time.Time `json:"expiration_time" mapstructure:"expiration_time"`

	// The time representing the last time this storage entry was modified
	LastUpdatedTime time.Time `json:"last_updated_time" mapstructure:"last_updated_time"`

	// Metadata that belongs to the SecretID
	Metadata map[string]string `json:"metadata" mapstructure:"metadata"`

	// CIDRList is a set of CIDR blocks that impose source address
	// restrictions on the usage of SecretID
	CIDRList []string `json:"cidr_list" mapstructure:"cidr_list"`

	// TokenBoundCIDRs is a set of CIDR blocks that impose source address
	// restrictions on the usage of the token generated by this SecretID
	TokenBoundCIDRs []string `json:"token_cidr_list" mapstructure:"token_bound_cidrs"`

	// This is a deprecated field
	SecretIDNumUsesDeprecated int `json:"SecretIDNumUses" mapstructure:"SecretIDNumUses"`
}

// Represents the payload of the storage entry of the accessor that maps to a
// unique SecretID. Note that SecretIDs should never be stored in plaintext
// anywhere in the backend. SecretIDHMAC will be used as an index to fetch the
// properties of the SecretID and to delete the SecretID.
type secretIDAccessorStorageEntry struct {
	// Hash of the SecretID which can be used to find the storage index at which
	// properties of SecretID is stored.
	SecretIDHMAC string `json:"secret_id_hmac" mapstructure:"secret_id_hmac"`
}

// verifyCIDRRoleSecretIDSubset checks if the CIDR blocks set on the secret ID
// are a subset of CIDR blocks set on the role
func verifyCIDRRoleSecretIDSubset(secretIDCIDRs []string, roleBoundCIDRList []string) error {
	if len(secretIDCIDRs) != 0 {
		// If there are no CIDR blocks on the role, then the subset
		// requirement would be satisfied
		if len(roleBoundCIDRList) != 0 {
			// Address blocks with /32 mask do not get stored with the CIDR mask
			// Check if there are any /32 addresses and append CIDR mask
			for i, block := range roleBoundCIDRList {
				if !strings.Contains(block, "/") {
					roleBoundCIDRList[i] = fmt.Sprint(block, "/32")
				}
			}

			subset, err := cidrutil.SubsetBlocks(roleBoundCIDRList, secretIDCIDRs)
			if !subset || err != nil {
				return fmt.Errorf(
					"failed to verify subset relationship between CIDR blocks on the role %q and CIDR blocks on the secret ID %q: %w",
					roleBoundCIDRList,
					secretIDCIDRs,
					err,
				)
			}
		}
	}

	return nil
}

const maxHmacInputLength = 4096

// Creates a SHA256 HMAC of the given 'value' using the given 'key' and returns
// a hex encoded string.
func createHMAC(key, value string) (string, error) {
	if key == "" {
		return "", errors.New("invalid HMAC key")
	}

	if len(value) > maxHmacInputLength {
		return "", fmt.Errorf("value is longer than maximum of %d bytes", maxHmacInputLength)
	}

	hm := hmac.New(sha256.New, []byte(key))
	hm.Write([]byte(value))
	return hex.EncodeToString(hm.Sum(nil)), nil
}

func (b *backend) secretIDLock(secretIDHMAC string) *locksutil.LockEntry {
	return locksutil.LockForKey(b.secretIDLocks, secretIDHMAC)
}

func (b *backend) secretIDAccessorLock(secretIDAccessor string) *locksutil.LockEntry {
	return locksutil.LockForKey(b.secretIDAccessorLocks, secretIDAccessor)
}

func decodeSecretIDStorageEntry(entry *logical.StorageEntry) (*secretIDStorageEntry, error) {
	result := secretIDStorageEntry{}
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	cleanup := func(in []string) []string {
		if len(in) == 0 {
			// Don't change unnecessarily, if it was empty list leave as empty list
			// instead of making it nil.
			return in
		}
		var out []string
		for _, s := range in {
			out = append(out, parseip.TrimLeadingZeroesCIDR(s))
		}
		return out
	}

	result.CIDRList = cleanup(result.CIDRList)
	result.TokenBoundCIDRs = cleanup(result.TokenBoundCIDRs)
	return &result, nil
}

// nonLockedSecretIDStorageEntry fetches the secret ID properties from physical
// storage. The entry will be indexed based on the given HMACs of both role
// name and the secret ID. This method will not acquire secret ID lock to fetch
// the storage entry. Locks need to be acquired before calling this method.
func (b *backend) nonLockedSecretIDStorageEntry(ctx context.Context, s logical.Storage, roleSecretIDPrefix, roleNameHMAC, secretIDHMAC string) (*secretIDStorageEntry, error) {
	if secretIDHMAC == "" {
		return nil, errors.New("missing secret ID HMAC")
	}

	if roleNameHMAC == "" {
		return nil, errors.New("missing role name HMAC")
	}

	// Prepare the storage index at which the secret ID will be stored
	entryIndex := fmt.Sprintf("%s%s/%s", roleSecretIDPrefix, roleNameHMAC, secretIDHMAC)

	entry, err := s.Get(ctx, entryIndex)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	result, err := decodeSecretIDStorageEntry(entry)
	if err != nil {
		return nil, err
	}

	// TODO: Remove this upgrade bit in future releases
	persistNeeded := false
	if result.SecretIDNumUsesDeprecated != 0 {
		if result.SecretIDNumUses == 0 ||
			result.SecretIDNumUsesDeprecated < result.SecretIDNumUses {
			result.SecretIDNumUses = result.SecretIDNumUsesDeprecated
			persistNeeded = true
		}
		if result.SecretIDNumUses < result.SecretIDNumUsesDeprecated {
			result.SecretIDNumUsesDeprecated = result.SecretIDNumUses
			persistNeeded = true
		}
	}

	if persistNeeded {
		if err := b.nonLockedSetSecretIDStorageEntry(ctx, s, roleSecretIDPrefix, roleNameHMAC, secretIDHMAC, result); err != nil {
			return nil, fmt.Errorf("failed to upgrade role storage entry %w", err)
		}
	}

	return result, nil
}

// nonLockedSetSecretIDStorageEntry creates or updates a secret ID entry at the
// physical storage. The entry will be indexed based on the given HMACs of both
// role name and the secret ID. This method will not acquire secret ID lock to
// create/update the storage entry. Locks need to be acquired before calling
// this method.
func (b *backend) nonLockedSetSecretIDStorageEntry(ctx context.Context, s logical.Storage, roleSecretIDPrefix, roleNameHMAC, secretIDHMAC string, secretEntry *secretIDStorageEntry) error {
	if roleSecretIDPrefix == "" {
		return errors.New("missing secret ID prefix")
	}
	if secretIDHMAC == "" {
		return errors.New("missing secret ID HMAC")
	}

	if roleNameHMAC == "" {
		return errors.New("missing role name HMAC")
	}

	if secretEntry == nil {
		return errors.New("nil secret entry")
	}

	entryIndex := fmt.Sprintf("%s%s/%s", roleSecretIDPrefix, roleNameHMAC, secretIDHMAC)

	if entry, err := logical.StorageEntryJSON(entryIndex, secretEntry); err != nil {
		return err
	} else if err = s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// registerSecretIDEntry creates a new storage entry for the given SecretID.
func (b *backend) registerSecretIDEntry(ctx context.Context, s logical.Storage, roleName, secretID, hmacKey, roleSecretIDPrefix string, secretEntry *secretIDStorageEntry) (*secretIDStorageEntry, error) {
	secretIDHMAC, err := createHMAC(hmacKey, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to create HMAC of secret ID: %w", err)
	}
	roleNameHMAC, err := createHMAC(hmacKey, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to create HMAC of role_name: %w", err)
	}

	lock := b.secretIDLock(secretIDHMAC)
	lock.RLock()

	entry, err := b.nonLockedSecretIDStorageEntry(ctx, s, roleSecretIDPrefix, roleNameHMAC, secretIDHMAC)
	if err != nil {
		lock.RUnlock()
		return nil, err
	}
	if entry != nil {
		lock.RUnlock()
		return nil, errors.New("SecretID is already registered")
	}

	// If there isn't an entry for the secretID already, switch the read lock
	// with a write lock and create an entry.
	lock.RUnlock()
	lock.Lock()
	defer lock.Unlock()

	// But before saving a new entry, check if the secretID entry was created during the lock switch.
	entry, err = b.nonLockedSecretIDStorageEntry(ctx, s, roleSecretIDPrefix, roleNameHMAC, secretIDHMAC)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		return nil, errors.New("SecretID is already registered")
	}

	//
	// Create a new entry for the SecretID
	//

	// Set the creation time for the SecretID
	currentTime := time.Now()
	secretEntry.CreationTime = currentTime
	secretEntry.LastUpdatedTime = currentTime

	if ttl := b.deriveSecretIDTTL(secretEntry.SecretIDTTL); ttl != time.Duration(0) {
		secretEntry.ExpirationTime = currentTime.Add(ttl)
	}

	// Before storing the SecretID, store its accessor.
	if err := b.createSecretIDAccessorEntry(ctx, s, secretEntry, secretIDHMAC, roleSecretIDPrefix); err != nil {
		return nil, err
	}

	if err := b.nonLockedSetSecretIDStorageEntry(ctx, s, roleSecretIDPrefix, roleNameHMAC, secretIDHMAC, secretEntry); err != nil {
		return nil, err
	}

	return secretEntry, nil
}

// deriveSecretIDTTL determines the secret ID TTL to use based on the system's
// max lease TTL.
//
// If SecretIDTTL is negative or if it crosses the backend mount's limit,
// return to backend's max lease TTL. Otherwise, return the provided secretIDTTL
// value.
func (b *backend) deriveSecretIDTTL(secretIDTTL time.Duration) time.Duration {
	if secretIDTTL < time.Duration(0) || secretIDTTL > b.System().MaxLeaseTTL() {
		return b.System().MaxLeaseTTL()
	}

	return secretIDTTL
}

// secretIDAccessorEntry is used to read the storage entry that maps an
// accessor to a secret_id.
func (b *backend) secretIDAccessorEntry(ctx context.Context, s logical.Storage, secretIDAccessor, roleSecretIDPrefix string) (*secretIDAccessorStorageEntry, error) {
	if secretIDAccessor == "" {
		return nil, errors.New("missing secretIDAccessor")
	}

	var result secretIDAccessorStorageEntry

	// Create index entry, mapping the accessor to the token ID
	salt, err := b.Salt(ctx)
	if err != nil {
		return nil, err
	}
	accessorPrefix := secretIDAccessorPrefix
	if roleSecretIDPrefix == secretIDLocalPrefix {
		accessorPrefix = secretIDAccessorLocalPrefix
	}
	entryIndex := accessorPrefix + salt.SaltID(secretIDAccessor)

	accessorLock := b.secretIDAccessorLock(secretIDAccessor)
	accessorLock.RLock()
	defer accessorLock.RUnlock()

	if entry, err := s.Get(ctx, entryIndex); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// createSecretIDAccessorEntry creates an identifier for the SecretID. A storage index,
// mapping the accessor to the SecretID is also created. This method should
// be called when the lock for the corresponding SecretID is held.
func (b *backend) createSecretIDAccessorEntry(ctx context.Context, s logical.Storage, entry *secretIDStorageEntry, secretIDHMAC, roleSecretIDPrefix string) error {
	// Create a random accessor
	accessorUUID, err := uuid.GenerateUUID()
	if err != nil {
		return err
	}
	entry.SecretIDAccessor = accessorUUID

	// Create index entry, mapping the accessor to the token ID
	salt, err := b.Salt(ctx)
	if err != nil {
		return err
	}

	accessorPrefix := secretIDAccessorPrefix
	if roleSecretIDPrefix == secretIDLocalPrefix {
		accessorPrefix = secretIDAccessorLocalPrefix
	}
	entryIndex := accessorPrefix + salt.SaltID(entry.SecretIDAccessor)

	accessorLock := b.secretIDAccessorLock(accessorUUID)
	accessorLock.Lock()
	defer accessorLock.Unlock()

	if entry, err := logical.StorageEntryJSON(entryIndex, &secretIDAccessorStorageEntry{
		SecretIDHMAC: secretIDHMAC,
	}); err != nil {
		return err
	} else if err = s.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to persist accessor index entry: %w", err)
	}

	return nil
}

// deleteSecretIDAccessorEntry deletes the storage index mapping the accessor to a SecretID.
func (b *backend) deleteSecretIDAccessorEntry(ctx context.Context, s logical.Storage, secretIDAccessor, roleSecretIDPrefix string) error {
	salt, err := b.Salt(ctx)
	if err != nil {
		return err
	}

	accessorPrefix := secretIDAccessorPrefix
	if roleSecretIDPrefix == secretIDLocalPrefix {
		accessorPrefix = secretIDAccessorLocalPrefix
	}
	entryIndex := accessorPrefix + salt.SaltID(secretIDAccessor)

	accessorLock := b.secretIDAccessorLock(secretIDAccessor)
	accessorLock.Lock()
	defer accessorLock.Unlock()

	// Delete the accessor of the SecretID first
	if err := s.Delete(ctx, entryIndex); err != nil {
		return fmt.Errorf("failed to delete accessor storage entry: %w", err)
	}

	return nil
}

// flushRoleSecrets deletes all the SecretIDs that belong to the given
// RoleID.
func (b *backend) flushRoleSecrets(ctx context.Context, s logical.Storage, roleName, hmacKey, roleSecretIDPrefix string) error {
	roleNameHMAC, err := createHMAC(hmacKey, roleName)
	if err != nil {
		return fmt.Errorf("failed to create HMAC of role_name: %w", err)
	}

	// Acquire the custom lock to perform listing of SecretIDs
	b.secretIDListingLock.RLock()
	defer b.secretIDListingLock.RUnlock()

	secretIDHMACs, err := s.List(ctx, fmt.Sprintf("%s%s/", roleSecretIDPrefix, roleNameHMAC))
	if err != nil {
		return err
	}
	for _, secretIDHMAC := range secretIDHMACs {
		// Acquire the lock belonging to the SecretID
		lock := b.secretIDLock(secretIDHMAC)
		lock.Lock()
		entryIndex := fmt.Sprintf("%s%s/%s", roleSecretIDPrefix, roleNameHMAC, secretIDHMAC)
		if err := s.Delete(ctx, entryIndex); err != nil {
			lock.Unlock()
			return fmt.Errorf("error deleting SecretID %q from storage: %w", secretIDHMAC, err)
		}
		lock.Unlock()
	}
	return nil
}
