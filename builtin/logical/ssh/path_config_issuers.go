package ssh

import (
	"context"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathConfigIssuers(b *backend) *framework.Path {
	configIssuerSchema := map[int][]framework.Response{
		http.StatusOK: {{
			Description: "OK",
			Fields: map[string]*framework.FieldSchema{
				"default": {
					Type:        framework.TypeString,
					Description: `Reference (name or identifier) to the default issuer.`,
					Required:    true,
				},
			},
		}},
	}
	return &framework.Path{
		Pattern: "config/issuers",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
			OperationSuffix: "issuer-config",
		},

		Fields: map[string]*framework.FieldSchema{
			defaultRef: {
				Type:        framework.TypeString,
				Description: `Reference (name or identifier) to the default issuer.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadDefaultIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "read",
				},
				Responses: configIssuerSchema,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathWriteDefaultIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "write",
				},
				Responses: configIssuerSchema,
			},
		},

		HelpSynopsis:    pathConfigIssuersSyn,
		HelpDescription: pathConfigIssuersDesc,
	}
}

func (b *backend) pathReadDefaultIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.getIssuersConfig()
	if err != nil {
		return handleStorageContextErr(err)
		// return logical.ErrorResponse("Error loading issuers configuration: " + err.Error()), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			defaultRef: config.DefaultIssuerID,
		},
	}, nil
}

func (b *backend) pathWriteDefaultIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	// Validate the new default reference.
	newDefault := getDefaultRef(d)
	if len(newDefault) == 0 || newDefault == defaultRef {
		return logical.ErrorResponse("Invalid issuer specification; must be non-empty and can't be 'default'."), nil
	}
	parsedIssuer, err := sc.resolveIssuerReference(newDefault)
	if err != nil {
		return handleStorageContextErr(err)
		// return logical.ErrorResponse("Error resolving issuer reference: " + err.Error()), nil
	}

	// Update the config
	config, err := sc.getIssuersConfig()
	if err != nil {
		// return logical.ErrorResponse("Unable to fetch existing issuers configuration: " + err.Error()), nil
		return handleStorageContextErr(err)
	}
	config.DefaultIssuerID = parsedIssuer

	if err := sc.setIssuersConfig(config); err != nil {
		// return logical.ErrorResponse("Error updating issuer configuration: " + err.Error()), nil
		return handleStorageContextErr(err)
	}

	// Commit our transaction if we created one!
	if txn, ok := req.Storage.(logical.Transaction); ok {
		if err := txn.Commit(ctx); err != nil {
			return nil, err
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			defaultRef: config.DefaultIssuerID,
		},
	}, nil
}

const (
	pathConfigIssuersSyn  = `Configure or read the default SSH certificate issuer.`
	pathConfigIssuersDesc = `
This endpoint allows configuring or reading the default issuer for SSH certificates.

The body parameter 'default' is the reference (name or identifier) to the default issuer.
`
)
