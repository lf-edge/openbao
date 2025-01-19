// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssh

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathFetchPublicKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `public_key`,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
			OperationSuffix: "public-key",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathFetchPublicKey,
			},
		},

		HelpSynopsis:    `Retrieve the 'default' issuer's public key.`,
		HelpDescription: `This endpoints allows fetching the configured default SSH issuer's public key. This is a raw response endpoint without JSON encoding; use -format=raw or an external tool (e.g., curl) to fetch this value.`,
	}
}

func (b *backend) pathFetchPublicKey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)

	issuer, err := sc.fetchDefaultIssuer()
	if err != nil {
		return handleStorageContextErr(err)
	}

	if issuer == nil {
		return logical.ErrorResponse("No key corresponding to issuer"), nil
	}

	response := &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "text/plain",
			logical.HTTPRawBody:     []byte(issuer.PublicKey),
			logical.HTTPStatusCode:  200,
		},
	}

	return response, nil
}
