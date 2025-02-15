// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const keysStoragePrefix = "keys/"

func pathCleanupKeys(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy/dynamic-keys",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
			OperationVerb:   "tidy",
			OperationSuffix: "dynamic-host-keys",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.handleCleanupKeys,
			},
		},
		HelpSynopsis:    `This endpoint removes the stored host keys used for the removed Dynamic Key feature, if present.`,
		HelpDescription: `For more information, refer to the API documentation.`,
	}
}

func (b *backend) handleCleanupKeys(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	names, err := req.Storage.List(ctx, keysStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("unable to list keys for removal: %w", err)
	}

	for index, name := range names {
		keyPath := keysStoragePrefix + name
		if err := req.Storage.Delete(ctx, keyPath); err != nil {
			return nil, fmt.Errorf("unable to delete key %v of %v: %w", index+1, len(names), err)
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"message": fmt.Sprintf("Removed %v of %v host keys.", len(names), len(names)),
		},
	}, nil
}
