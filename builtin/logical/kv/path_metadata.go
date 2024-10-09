package kv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mitchellh/mapstructure"

	"github.com/golang/protobuf/ptypes"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathMetadata returns the path configuration for CRUD operations on the
// metadata endpoint
func pathMetadata(b *versionedKVBackend) *framework.Path {
	return &framework.Path{
		Pattern: "metadata/" + framework.MatchAllRegex("path"),
		Fields: map[string]*framework.FieldSchema{
			"path": {
				Type:        framework.TypeString,
				Description: "Location of the secret.",
			},
			"cas_required": {
				Type: framework.TypeBool,
				Description: `
If true the key will require the cas parameter to be set on all write requests.
If false, the backend’s configuration will be used.`,
			},
			"max_versions": {
				Type: framework.TypeInt,
				Description: `
The number of versions to keep. If not set, the backend’s configured max
version is used.`,
			},
			"delete_version_after": {
				Type: framework.TypeDurationSecond,
				Description: `
The length of time before a version is deleted. If not set, the backend's
configured delete_version_after is used. Cannot be greater than the
backend's delete_version_after. A zero duration clears the current setting.
A negative duration will cause an error.
`,
			},
			"custom_metadata": {
				Type: framework.TypeMap,
				Description: `
User-provided key-value pairs that are used to describe arbitrary and
version-agnostic information about a secret.
`,
			},
			"after": {
				Type:        framework.TypeString,
				Description: `Optional entry to list begin listing after, not required to exist. Only used for listing.`,
			},
			"limit": {
				Type:        framework.TypeInt,
				Description: `Optional number of entries to return; defaults to all entries. Only used for listing.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.upgradeCheck(b.pathMetadataWrite()),
			logical.CreateOperation: b.upgradeCheck(b.pathMetadataWrite()),
			logical.ReadOperation:   b.upgradeCheck(b.pathMetadataRead()),
			logical.DeleteOperation: b.upgradeCheck(b.pathMetadataDelete()),
			logical.ListOperation:   b.upgradeCheck(b.pathMetadataList()),
			logical.PatchOperation:  b.upgradeCheck(b.pathMetadataPatch()),
		},

		ExistenceCheck: b.metadataExistenceCheck(),

		HelpSynopsis:    metadataHelpSyn,
		HelpDescription: metadataHelpDesc,
	}
}

func (b *versionedKVBackend) metadataExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		key := data.Get("path").(string)

		meta, err := b.getKeyMetadata(ctx, req.Storage, key)
		if err != nil {
			// If we are returning a readonly error it means we are attempting
			// to write the policy for the first time. This means no data exists
			// yet and we can safely return false here.
			if strings.Contains(err.Error(), logical.ErrReadOnly.Error()) {
				return false, nil
			}

			return false, err
		}

		return meta != nil, nil
	}
}

func (b *versionedKVBackend) pathMetadataList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		after := data.Get("after").(string)
		limit := data.Get("limit").(int)
		if limit <= 0 {
			limit = -1
		}

		key := data.Get("path").(string)

		// Get an encrypted key storage object
		wrapper, err := b.getKeyEncryptor(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		es := wrapper.Wrap(req.Storage)

		// Use encrypted key storage to list the keys
		keys, err := es.ListPage(ctx, key, after, limit)
		return logical.ListResponse(keys), err
	}
}

func (b *versionedKVBackend) pathMetadataRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// Create a read-only transaction if we can. We do not need to commit
		// this as we're not writing to storage.
		if txnStorage, ok := req.Storage.(logical.TransactionalStorage); ok {
			txn, err := txnStorage.BeginReadOnlyTx(ctx)
			if err != nil {
				return nil, err
			}

			defer txn.Rollback(ctx)
			req.Storage = txn
		}

		key := data.Get("path").(string)

		meta, err := b.getKeyMetadata(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}
		if meta == nil {
			return nil, nil
		}

		versions := make(map[string]interface{}, len(meta.Versions))
		for i, v := range meta.Versions {
			versions[fmt.Sprintf("%d", i)] = map[string]interface{}{
				"created_time":  ptypesTimestampToString(v.CreatedTime),
				"deletion_time": ptypesTimestampToString(v.DeletionTime),
				"destroyed":     v.Destroyed,
			}
		}

		var deleteVersionAfter time.Duration
		if meta.GetDeleteVersionAfter() != nil {
			deleteVersionAfter, err = ptypes.Duration(meta.GetDeleteVersionAfter())
			if err != nil {
				return nil, err
			}
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"versions":             versions,
				"current_version":      meta.CurrentVersion,
				"oldest_version":       meta.OldestVersion,
				"created_time":         ptypesTimestampToString(meta.CreatedTime),
				"updated_time":         ptypesTimestampToString(meta.UpdatedTime),
				"max_versions":         meta.MaxVersions,
				"cas_required":         meta.CasRequired,
				"delete_version_after": deleteVersionAfter.String(),
				"custom_metadata":      meta.CustomMetadata,
			},
		}, nil
	}
}

const (
	maxCustomMetadataKeys               = 64
	maxCustomMetadataKeyLength          = 128
	maxCustomMetadataValueLength        = 512
	customMetadataValidationErrorPrefix = "custom_metadata validation failed"
)

// Perform input validation on custom_metadata field. If the key count
// exceeds maxCustomMetadataKeys, the validation will be short-circuited
// to prevent unnecessary (and potentially costly) validation to be run.
// If the key count falls at or below maxCustomMetadataKeys, multiple
// checks will be made per key and value. These checks include:
//   - 0 < length of key <= maxCustomMetadataKeyLength
//   - 0 < length of value <= maxCustomMetadataValueLength
//   - keys and values cannot include unprintable characters
func validateCustomMetadata(customMetadata map[string]string) error {
	var errs *multierror.Error

	if keyCount := len(customMetadata); keyCount > maxCustomMetadataKeys {
		errs = multierror.Append(errs, fmt.Errorf("%s: payload must contain at most %d keys, provided %d",
			customMetadataValidationErrorPrefix,
			maxCustomMetadataKeys,
			keyCount))

		return errs.ErrorOrNil()
	}

	// Perform validation on each key and value and return ALL errors
	for key, value := range customMetadata {
		if keyLen := len(key); 0 == keyLen || keyLen > maxCustomMetadataKeyLength {
			errs = multierror.Append(errs, fmt.Errorf("%s: length of key %q is %d but must be 0 < len(key) <= %d",
				customMetadataValidationErrorPrefix,
				key,
				keyLen,
				maxCustomMetadataKeyLength))
		}

		if valueLen := len(value); 0 == valueLen || valueLen > maxCustomMetadataValueLength {
			errs = multierror.Append(errs, fmt.Errorf("%s: length of value for key %q is %d but must be 0 < len(value) <= %d",
				customMetadataValidationErrorPrefix,
				key,
				valueLen,
				maxCustomMetadataValueLength))
		}

		if !strutil.Printable(key) {
			// Include unquoted format (%s) to also include the string without the unprintable
			//  characters visible to allow for easier debug and key identification
			errs = multierror.Append(errs, fmt.Errorf("%s: key %q (%s) contains unprintable characters",
				customMetadataValidationErrorPrefix,
				key,
				key))
		}

		if !strutil.Printable(value) {
			errs = multierror.Append(errs, fmt.Errorf("%s: value for key %q contains unprintable characters",
				customMetadataValidationErrorPrefix,
				key))
		}
	}

	return errs.ErrorOrNil()
}

// parseCustomMetadata is used to effectively convert the TypeMap
// (map[string]interface{}) into a TypeKVPairs (map[string]string)
// which is how custom_metadata is stored. Defining custom_metadata
// as a TypeKVPairs will convert nulls into empty strings. A null,
// however, is essential for a PATCH operation in that it signals
// the handler to remove the field. The filterNils flag should
// only be used during a patch operation.
func parseCustomMetadata(raw map[string]interface{}, filterNils bool) (map[string]string, error) {
	customMetadata := map[string]string{}
	for k, v := range raw {
		if filterNils && v == nil {
			continue
		}

		var s string
		if err := mapstructure.WeakDecode(v, &s); err != nil {
			return nil, err
		}

		customMetadata[k] = s
	}

	return customMetadata, nil
}

func (b *versionedKVBackend) pathMetadataWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		key := data.Get("path").(string)
		if key == "" {
			return logical.ErrorResponse("missing path"), nil
		}

		maxRaw, mOk := data.GetOk("max_versions")
		casRaw, cOk := data.GetOk("cas_required")
		deleteVersionAfterRaw, dvaOk := data.GetOk("delete_version_after")
		customMetadataRaw, cmOk := data.GetOk("custom_metadata")

		// Fast path validation
		if !mOk && !cOk && !dvaOk && !cmOk {
			return nil, nil
		}

		config, err := b.config(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		customMetadataMap := map[string]string{}

		if cmOk {
			customMetadataMap, err = parseCustomMetadata(customMetadataRaw.(map[string]interface{}), false)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("%s: %s", customMetadataValidationErrorPrefix, err.Error())), nil
			}

			customMetadataErrs := validateCustomMetadata(customMetadataMap)

			if customMetadataErrs != nil {
				return logical.ErrorResponse(customMetadataErrs.Error()), nil
			}
		}

		var resp *logical.Response
		if cOk && config.CasRequired && !casRaw.(bool) {
			resp = &logical.Response{}
			resp.AddWarning("\"cas_required\" set to false, but is mandated by backend config. This value will be ignored.")
		}

		lock := locksutil.LockForKey(b.locks, key)
		lock.Lock()
		defer lock.Unlock()

		// Create a transaction if we can.
		originalStorage := req.Storage
		if txnStorage, ok := req.Storage.(logical.TransactionalStorage); ok {
			txn, err := txnStorage.BeginTx(ctx)
			if err != nil {
				return nil, err
			}

			defer txn.Rollback(ctx)
			req.Storage = txn
		}

		meta, err := b.getKeyMetadata(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}
		if meta == nil {
			now := ptypes.TimestampNow()
			meta = &KeyMetadata{
				Key:         key,
				Versions:    map[uint64]*VersionMetadata{},
				CreatedTime: now,
				UpdatedTime: now,
			}
		}

		if mOk {
			meta.MaxVersions = uint32(maxRaw.(int))
		}
		if cOk {
			meta.CasRequired = casRaw.(bool)
		}
		if dvaOk {
			meta.DeleteVersionAfter = ptypes.DurationProto(time.Duration(deleteVersionAfterRaw.(int)) * time.Second)
		}
		if cmOk {
			meta.CustomMetadata = customMetadataMap
		}

		err = b.writeKeyMetadata(ctx, req.Storage, meta)
		if err == nil {
			// Commit our transaction if we created one! We're done making
			// modifications to storage.
			if txn, ok := req.Storage.(logical.Transaction); ok && req.Storage != originalStorage {
				if err := txn.Commit(ctx); err != nil {
					return nil, err
				}
				req.Storage = originalStorage
			}
		}

		return resp, err
	}
}

// metadataPatchPreprocessor returns a framework.PatchPreprocessorFunc meant to
// be provided to framework.HandlePatchOperation. The returned
// framework.PatchPreprocessorFunc handles filtering out Vault-managed fields,
// and ensuring appropriate handling of data types not supported directly by FieldType.
func metadataPatchPreprocessor() framework.PatchPreprocessorFunc {
	return func(input map[string]interface{}) (map[string]interface{}, error) {
		patchableKeys := []string{"max_versions", "cas_required", "delete_version_after", "custom_metadata"}
		patchData := map[string]interface{}{}

		for _, k := range patchableKeys {
			if v, ok := input[k]; ok {
				if k == "delete_version_after" {
					patchData[k] = ptypes.DurationProto(time.Duration(v.(int)) * time.Second)
				} else {
					patchData[k] = v
				}
			}
		}

		return patchData, nil
	}
}

// pathMetadataPatch handles a PatchOperation request for a secret's key metadata
// The key metadata entry must exist to apply the provided patch data.
func (b *versionedKVBackend) pathMetadataPatch() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		key := data.Get("path").(string)

		if key == "" {
			return logical.ErrorResponse("missing path"), nil
		}

		if cmRaw, cmOk := data.GetOk("custom_metadata"); cmOk {
			customMetadataMap, err := parseCustomMetadata(cmRaw.(map[string]interface{}), true)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("%s: %s", customMetadataValidationErrorPrefix, err.Error())), nil
			}

			customMetadataErrs := validateCustomMetadata(customMetadataMap)

			if customMetadataErrs != nil {
				return logical.ErrorResponse(customMetadataErrs.Error()), nil
			}
		}

		config, err := b.config(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		lock := locksutil.LockForKey(b.locks, key)
		lock.Lock()
		defer lock.Unlock()

		// Create a transaction if we can.
		originalStorage := req.Storage
		if txnStorage, ok := req.Storage.(logical.TransactionalStorage); ok {
			txn, err := txnStorage.BeginTx(ctx)
			if err != nil {
				return nil, err
			}

			defer txn.Rollback(ctx)
			req.Storage = txn
		}

		meta, err := b.getKeyMetadata(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}

		if meta == nil {
			return logical.RespondWithStatusCode(nil, req, http.StatusNotFound)
		}

		var resp *logical.Response
		casRaw, cOk := data.GetOk("cas_required")

		if cOk && config.CasRequired && !casRaw.(bool) {
			resp = &logical.Response{}
			resp.AddWarning("\"cas_required\" set to false, but is mandated by backend config. This value will be ignored.")
		}

		// proto-generated structs do not have mapstructure tags so marshal
		// metadata here so that map keys are consistent with request data
		metadataJSON, err := json.Marshal(meta)
		if err != nil {
			return nil, err
		}

		var metaMap map[string]interface{}
		if err = json.Unmarshal(metadataJSON, &metaMap); err != nil {
			return nil, err
		}

		patchedBytes, err := framework.HandlePatchOperation(data, metaMap, metadataPatchPreprocessor())
		if err != nil {
			return nil, err
		}

		var patchedMetadata *KeyMetadata
		if err = json.Unmarshal(patchedBytes, &patchedMetadata); err != nil {
			return nil, err
		}

		if err = b.writeKeyMetadata(ctx, req.Storage, patchedMetadata); err != nil {
			return nil, err
		}

		// Commit our transaction if we created one! We're done making
		// modifications to storage.
		if txn, ok := req.Storage.(logical.Transaction); ok && req.Storage != originalStorage {
			if err := txn.Commit(ctx); err != nil {
				return nil, err
			}
			req.Storage = originalStorage
		}

		return resp, nil
	}
}

func (b *versionedKVBackend) pathMetadataDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		key := data.Get("path").(string)

		lock := locksutil.LockForKey(b.locks, key)
		lock.Lock()
		defer lock.Unlock()

		// Create a transaction if we can.
		originalStorage := req.Storage
		if txnStorage, ok := req.Storage.(logical.TransactionalStorage); ok {
			txn, err := txnStorage.BeginTx(ctx)
			if err != nil {
				return nil, err
			}

			defer txn.Rollback(ctx)
			req.Storage = txn
		}

		meta, err := b.getKeyMetadata(ctx, req.Storage, key)
		if err != nil {
			return nil, err
		}
		if meta == nil {
			return nil, nil
		}

		// Delete each version.
		for id := range meta.Versions {
			versionKey, err := b.getVersionKey(ctx, key, id, req.Storage)
			if err != nil {
				return nil, err
			}

			err = req.Storage.Delete(ctx, versionKey)
			if err != nil {
				return nil, err
			}
		}

		// Get an encrypted key storage object
		wrapper, err := b.getKeyEncryptor(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		es := wrapper.Wrap(req.Storage)

		// Use encrypted key storage to delete the key
		err = es.Delete(ctx, key)
		if err == nil {
			// Commit our transaction if we created one! We're done making
			// modifications to storage.
			if txn, ok := req.Storage.(logical.Transaction); ok && req.Storage != originalStorage {
				if err := txn.Commit(ctx); err != nil {
					return nil, err
				}
				req.Storage = originalStorage
			}
		}
		return nil, err
	}
}

const (
	metadataHelpSyn  = `Allows interaction with key metadata and settings in the KV store.`
	metadataHelpDesc = `
This endpoint allows for reading, information about a key in the key-value
store, writing key settings, and permanently deleting a key and all versions. 
`
)
