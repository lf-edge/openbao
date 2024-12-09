package ssh

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathIssuers(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "issuer/" + framework.GenericNameRegex("issuer_ref"),
		// TODO: Display attrs
		DisplayAttrs: &framework.DisplayAttributes{},
		Fields: map[string]*framework.FieldSchema{
			"issuer_ref": {
				Type:        framework.TypeString,
				Description: `Issuer reference. It can be the issuer's unique identifier, or the optionally given name.`,
			},
			"issuer_name": {
				Type:        framework.TypeString,
				Required:    false,
				Description: `Issuer name.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "read",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUpdateIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "update",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "delete",
				},
			},
		},
		HelpSynopsis:    "",
		HelpDescription: "",
	}
}

func pathSubmitIssuer(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "issuers/import" + framework.OptionalGenericNameRegex("issuer_name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
		},

		Fields: map[string]*framework.FieldSchema{
			"issuer_name": {
				Type:        framework.TypeString,
				Required:    false,
				Description: `Optional issuer name. If not provided, the name will be the same as the issuer reference.`,
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: `Private half of the SSH key that will be used to sign certificates.`,
			},
			"public_key": {
				Type:        framework.TypeString,
				Description: `Public half of the SSH key that will be used to sign certificates.`,
			},
			"generate_signing_key": {
				Type:        framework.TypeBool,
				Description: `Generate SSH key pair internally rather than use the private_key and public_key fields.`,
				Default:     true,
			},
			"key_type": {
				Type:        framework.TypeString,
				Description: `Specifies the desired key type when generating; could be a OpenSSH key type identifier (ssh-rsa, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, or ssh-ed25519) or an algorithm (rsa, ec, ed25519).`,
				Default:     "ssh-rsa",
			},
			"key_bits": {
				Type:        framework.TypeInt,
				Description: `Specifies the desired key bits when generating variable-length keys (such as when key_type="ssh-rsa") or which NIST P-curve to use when key_type="ec" (256, 384, or 521).`,
				Default:     0,
			},
			"set_default": {
				Type:        framework.TypeBool,
				Description: `If true, this issuer will be set as the default issuer for performing operations. Only one issuer can be the default issuer and, if there's one set, it will be overrided.`,
				Default:     false,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathWriteIssuerHandler,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "submit",
					OperationSuffix: "issuer",
				},
			},
		},

		HelpSynopsis:    "",
		HelpDescription: "",
	}
}

func pathListIssuers(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "issuers/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
			OperationSuffix: "issuers",
		},

		Fields: map[string]*framework.FieldSchema{
			"after": {
				Type:        framework.TypeString,
				Required:    false,
				Description: `Optional entry to list begin listing after, not required to exist.`,
			},
			"limit": {
				Type:        framework.TypeInt,
				Required:    false,
				Description: `Optional number of entries to return; defaults to all entries.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathListIssuersHandler,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"keys": {
								Type:        framework.TypeStringSlice,
								Description: `A list of keys`,
								Required:    true,
							},
							"key_info": {
								Type:        framework.TypeMap,
								Description: `Key info with issuer identifier`,
								Required:    false,
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

func pathGetIssuerUnauthenticated(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "issuer/" + framework.GenericNameRegex("issuer_ref") + "/public_key",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixSSH,
			// OperationSuffix: "issuers",
		},

		Fields: map[string]*framework.FieldSchema{
			"issuer_ref": {
				Type:        framework.TypeString,
				Description: `Issuer reference. It can be the issuer's unique identifier, or the optionally given name.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadIssuerHandler,
				Responses: map[int][]framework.Response{
					http.StatusOK: {
						{
							Description: "OK",
							// TODO: Add
							Fields: map[string]*framework.FieldSchema{},
						},
					},
				},
			},
		},

		HelpSynopsis:    "",
		HelpDescription: "",
	}
}

func (b *backend) pathReadIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	issuerRef := getIssuerRef(d)

	sc := b.makeStorageContext(ctx, req.Storage)
	id, err := sc.resolveIssuerReference(issuerRef)
	if err != nil {
		return handleStorageContextErr(err)
	}

	entry, err := sc.fetchIssuerById(id)
	if err != nil {
		return handleStorageContextErr(err)
	}

	return respondReadIssuer(entry)
}

func (b *backend) pathUpdateIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Since we're planning on updating issuers here, grab the lock so we've
	// got a consistent view.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	issuerRef := getIssuerRef(d)

	sc := b.makeStorageContext(ctx, req.Storage)
	id, err := sc.resolveIssuerReference(issuerRef)
	if err != nil {
		return handleStorageContextErr(err)
	}

	issuer, err := sc.fetchIssuerById(id)
	if err != nil {
		return handleStorageContextErr(err)
	}

	newName, err := getIssuerName(sc, d)
	if err != nil {
		switch err {
		// If the error is name already in use, and the new name is the
		// old name for this issuer, we're not actually updating the
		// issuer name (or causing a conflict) -- so don't err out. Other
		// errs should still be surfaced.
		case errIssuerNameInUse:
			if issuer.Name != newName {
				// When the new name is in use but isn't this name, throw an error.
				return logical.ErrorResponse(err.Error()), nil
			}
			return respondReadIssuer(issuer)
		default:
			return handleStorageContextErr(err)
		}
	}

	oldName := issuer.Name
	issuer.Name = newName

	err = sc.writeIssuer(issuer)
	if err != nil {
		return handleStorageContextErr(err)
	}

	response, _ := respondReadIssuer(issuer)
	addWarningOnDereferencing(sc, oldName, response)

	return response, nil
}

func (b *backend) pathDeleteIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Since we're planning on updating issuers here, grab the lock so we've
	// got a consistent view.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	issuerRef := getIssuerRef(d)

	sc := b.makeStorageContext(ctx, req.Storage)
	id, err := sc.resolveIssuerReference(issuerRef)
	if err != nil {
		// Return as if we deleted it if we fail to lookup the issuer.
		if id == IssuerRefNotFound {
			return &logical.Response{}, nil
		}
		return handleStorageContextErr(err)
	}

	response := &logical.Response{}

	issuer, err := sc.fetchIssuerById(id)
	if err != nil {
		return nil, err
	}
	if issuer.Name != "" {
		addWarningOnDereferencing(sc, issuer.Name, response)
	}
	addWarningOnDereferencing(sc, string(issuer.ID), response)

	wasDefault, err := sc.deleteIssuer(id)
	if err != nil {
		return nil, err
	}

	if wasDefault {
		response.AddWarning(fmt.Sprintf("Deleted issuer %v (via issuer_ref %v); this was configured as the default issuer. Operations without an explicit issuer will not work until a new default is configured.", id, issuerRef))
		addWarningOnDereferencing(sc, defaultRef, response)
	}

	return response, nil
}

func (b *backend) pathWriteIssuerHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Since we're planning on updating issuers here, grab the lock so we've
	// got a consistent view.
	b.issuersLock.Lock()
	defer b.issuersLock.Unlock()

	publicKey, privateKey, err := b.keys(d)
	if err != nil {
		switch err.(type) {
		case errutil.InternalError:
			return nil, err
		default:
			return logical.ErrorResponse(err.Error()), nil
		}
	}

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

	// Create a new issuer entry
	id, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("error generating issuer's unique identifier: %w", err)
	}
	name, err := getIssuerName(sc, d)
	if err != nil && err != errIssuerNameIsEmpty {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		default:
			return nil, err
		}
	}
	issuer := &issuerEntry{
		ID:         issuerID(id),
		Name:       name,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Version:    1,
	}

	err = sc.writeIssuer(issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to persist the issuer: %w", err)
	}

	// NOTE: Return `is_default`?
	response, err := respondReadIssuer(issuer)

	setDefault := d.Get("set_default").(bool)
	if setDefault {
		// Update issuers config to set new issuer as the 'default'
		err = sc.setIssuersConfig(&issuerConfigEntry{DefaultIssuerID: issuerID(id)})
		if err != nil {
			// It is not possible to have this error in the transaction, so check
			// storage type and skip if is a transaction
			if _, ok := req.Storage.(logical.Transaction); !ok {
				// Even if the new issuer fails to be set as default, we want to return
				// the newly submitted issuer with a warning
				response.AddWarning(fmt.Sprintf("Unable to update the default issuers configuration: %s", err.Error()))
			}
		}
	}

	// Commit our transaction if we created one!
	if txn, ok := req.Storage.(logical.Transaction); ok {
		if err := txn.Commit(ctx); err != nil {
			return nil, err
		}
	}

	// Whether an key material is generated or submitted, we return the issuer's data always.
	return response, nil
}

func (b *backend) pathListIssuersHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var responseKeys []string
	responseInfo := make(map[string]interface{})

	after := d.Get("after").(string)
	limit := d.Get("limit").(int)

	sc := b.makeStorageContext(ctx, req.Storage)
	entries, err := sc.listIssuersPage(after, limit)
	if err != nil {
		return nil, err
	}

	config, err := sc.getIssuersConfig()
	if err != nil {
		return nil, err
	}

	// For each issuer, we need not only the identifier (as returned by
	// listIssuers), but also the name of the issuer and its public key.
	// This means we have to fetch the actual issuer object as well.
	for _, identifier := range entries {
		issuer, err := sc.fetchIssuerById(identifier)
		if err != nil {
			return nil, err
		}

		responseKeys = append(responseKeys, string(identifier))
		responseInfo[string(identifier)] = map[string]interface{}{
			"issuer_name": issuer.Name,
			"is_default":  identifier == config.DefaultIssuerID,
			"public_key":  issuer.PublicKey,
		}
	}

	return logical.ListResponseWithInfo(responseKeys, responseInfo), nil
}

func respondReadIssuer(issuer *issuerEntry) (*logical.Response, error) {
	data := map[string]interface{}{
		"issuer_id":   issuer.ID,
		"issuer_name": issuer.Name,
		"public_key":  issuer.PublicKey,
	}

	response := &logical.Response{
		Data: data,
	}

	return response, nil
}

func addWarningOnDereferencing(sc *storageContext, name string, resp *logical.Response) {
	timeout, inUseBy, err := sc.checkForRolesReferencingIssuer(name)
	if err != nil || timeout {
		if inUseBy == 0 {
			resp.AddWarning(fmt.Sprintf("Unable to check if any roles referenced this issuer by '%s'", name))
		} else {
			resp.AddWarning(fmt.Sprint("The name '%s' was in use by at least %d roles", name, inUseBy))
		}
	} else {
		if inUseBy > 0 {
			resp.AddWarning(fmt.Sprintf("%d roles reference '%s'", inUseBy, name))
		}
	}
}
