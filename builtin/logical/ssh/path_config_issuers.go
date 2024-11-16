package ssh

import (
	"context"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathConfigIssuers(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/issuers",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
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
					OperationSuffix: "issuers-configuration",
				},
				Responses: map[int][]framework.Response{
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
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathWriteDefaultIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "issuers",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"default": {
								Type:        framework.TypeString,
								Description: `Reference (name or identifier) to the default issuer.`,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    "",
		HelpDescription: "",
	}
}

func (b *backend) pathReadDefaultIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	sc := b.makeStorageContext(ctx, req.Storage)
	config, err := sc.getIssuersConfig()
	if err != nil {
		// NOTE: internal err?
		return logical.ErrorResponse("Error loading issuers configuration: " + err.Error()), nil
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

	sc := b.makeStorageContext(ctx, req.Storage)

	// Validate the new default reference.
	newDefault := d.Get(defaultRef).(string)
	if len(newDefault) == 0 || newDefault == defaultRef {
		return logical.ErrorResponse("Invalid issuer specification; must be non-empty and can't be 'default'."), nil
	}
	parsedIssuer, err := sc.resolveIssuerReference(newDefault)
	if err != nil {
		return logical.ErrorResponse("Error resolving issuer reference: " + err.Error()), nil
	}

	// Update the config
	config, err := sc.getIssuersConfig()
	if err != nil {
		return logical.ErrorResponse("Unable to fetch existing issuers configuration: " + err.Error()), nil
	}
	config.DefaultIssuerID = parsedIssuer

	if err := sc.setIssuersConfig(config); err != nil {
		return logical.ErrorResponse("Error updating issuer configuration: " + err.Error()), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			defaultRef: config.DefaultIssuerID,
		},
	}, nil
}
