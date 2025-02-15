// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ldap

import (
	"context"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/ldaputil"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const userFilterWarning = "userfilter configured does not consider userattr and may result in colliding entity aliases on logins"

func pathConfig(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: `config`,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixLDAP,
			Action:          "Configure",
		},

		Fields: ldaputil.ConfigFields(),

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "auth-configuration",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure-auth",
				},
			},
		},

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}

	tokenutil.AddTokenFields(p.Fields)
	p.Fields["token_policies"].Description += ". This will apply to all tokens generated by this auth method, in addition to any configured for specific users/groups."
	return p
}

/*
 * Construct ConfigEntry struct using stored configuration.
 */
func (b *backend) Config(ctx context.Context, req *logical.Request) (*ldapConfigEntry, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	storedConfig, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	if storedConfig == nil {
		// Create a new ConfigEntry, filling in defaults where appropriate
		fd, err := b.getConfigFieldData()
		if err != nil {
			return nil, err
		}

		result, err := ldaputil.NewConfigEntry(nil, fd)
		if err != nil {
			return nil, err
		}

		// No user overrides, return default configuration
		result.CaseSensitiveNames = new(bool)
		*result.CaseSensitiveNames = false

		result.UsePre111GroupCNBehavior = new(bool)
		*result.UsePre111GroupCNBehavior = false

		return &ldapConfigEntry{ConfigEntry: result}, nil
	}

	// Deserialize stored configuration.
	// Fields not specified in storedConfig will retain their defaults.
	result := new(ldapConfigEntry)
	result.ConfigEntry = new(ldaputil.ConfigEntry)
	if err := storedConfig.DecodeJSON(result); err != nil {
		return nil, err
	}

	var persistNeeded bool
	if result.CaseSensitiveNames == nil {
		// Upgrade from before switching to case-insensitive
		result.CaseSensitiveNames = new(bool)
		*result.CaseSensitiveNames = true
		persistNeeded = true
	}

	if result.UsePre111GroupCNBehavior == nil {
		result.UsePre111GroupCNBehavior = new(bool)
		*result.UsePre111GroupCNBehavior = true
		persistNeeded = true
	}

	if persistNeeded && (b.System().LocalMount() || !b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary|consts.ReplicationPerformanceStandby)) {
		entry, err := logical.StorageEntryJSON("config", result)
		if err != nil {
			return nil, err
		}
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, err
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return result, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.Config(ctx, req)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	data := cfg.PasswordlessMap()
	cfg.PopulateTokenData(data)

	resp := &logical.Response{
		Data: data,
	}

	if warnings := b.checkConfigUserFilter(cfg); len(warnings) > 0 {
		resp.Warnings = warnings
	}

	return resp, nil
}

// checkConfigUserFilter performs a best-effort check the config's userfilter.
// It will checked whether the templated or literal userattr value is present,
// and if not return a warning.
func (b *backend) checkConfigUserFilter(cfg *ldapConfigEntry) []string {
	if cfg == nil || cfg.UserFilter == "" {
		return nil
	}

	var warnings []string

	switch {
	case strings.Contains(cfg.UserFilter, "{{.UserAttr}}"):
		// Case where the templated userattr value is provided
	case strings.Contains(cfg.UserFilter, cfg.UserAttr):
		// Case where the literal userattr value is provided
	default:
		b.Logger().Debug(userFilterWarning, "userfilter", cfg.UserFilter, "userattr", cfg.UserAttr)
		warnings = append(warnings, userFilterWarning)
	}

	return warnings
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	cfg, err := b.Config(ctx, req)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	// Build a ConfigEntry struct out of the supplied FieldData
	cfg.ConfigEntry, err = ldaputil.NewConfigEntry(cfg.ConfigEntry, d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// On write, if not specified, use false. We do this here so upgrade logic
	// works since it calls the same newConfigEntry function
	if cfg.CaseSensitiveNames == nil {
		cfg.CaseSensitiveNames = new(bool)
		*cfg.CaseSensitiveNames = false
	}

	if cfg.UsePre111GroupCNBehavior == nil {
		cfg.UsePre111GroupCNBehavior = new(bool)
		*cfg.UsePre111GroupCNBehavior = false
	}

	if err := cfg.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	if warnings := b.checkConfigUserFilter(cfg); len(warnings) > 0 {
		return &logical.Response{
			Warnings: warnings,
		}, nil
	}

	return nil, nil
}

/*
 * Returns FieldData describing our ConfigEntry struct schema
 */
func (b *backend) getConfigFieldData() (*framework.FieldData, error) {
	configPath := b.Route("config")

	if configPath == nil {
		return nil, logical.ErrUnsupportedPath
	}

	raw := make(map[string]interface{}, len(configPath.Fields))

	fd := framework.FieldData{
		Raw:    raw,
		Schema: configPath.Fields,
	}

	return &fd, nil
}

type ldapConfigEntry struct {
	tokenutil.TokenParams
	*ldaputil.ConfigEntry
}

const pathConfigHelpSyn = `
Configure the LDAP server to connect to, along with its options.
`

const pathConfigHelpDesc = `
This endpoint allows you to configure the LDAP server to connect to and its
configuration options.

The LDAP URL can use either the "ldap://" or "ldaps://" schema. In the former
case, an unencrypted connection will be made with a default port of 389, unless
the "starttls" parameter is set to true, in which case TLS will be used. In the
latter case, a SSL connection will be established with a default port of 636.

## A NOTE ON ESCAPING

It is up to the administrator to provide properly escaped DNs. This includes
the user DN, bind DN for search, and so on.

The only DN escaping performed by this backend is on usernames given at login
time when they are inserted into the final bind DN, and uses escaping rules
defined in RFC 4514.

Additionally, Active Directory has escaping rules that differ slightly from the
RFC; in particular it requires escaping of '#' regardless of position in the DN
(the RFC only requires it to be escaped when it is the first character), and
'=', which the RFC indicates can be escaped with a backslash, but does not
contain in its set of required escapes. If you are using Active Directory and
these appear in your usernames, please ensure that they are escaped, in
addition to being properly escaped in your configured DNs.

For reference, see https://www.ietf.org/rfc/rfc4514.txt and
http://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx
`
