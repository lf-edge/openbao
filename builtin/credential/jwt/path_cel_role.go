// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-sockaddr"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type celRoleEntry struct {
	Name          string `json:"name"`                     // Required
	AuthProgram   string `json:"auth_program"`             // Required
	FailurePolicy string `json:"failure_policy,omitempty"` // Defaults to "Deny"
	Message       string `json:"message,omitempty"`
}

type celRole struct {
	tokenutil.TokenParams
}

func pathCelRoleList(b *jwtAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "cel/role/?",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixJWT,
			OperationSuffix: "cel",
			OperationVerb:   "list",
		},

		Fields: map[string]*framework.FieldSchema{
			"after": {
				Type:        framework.TypeString,
				Description: `Optional entry to list begin listing after, not required to exist.`,
			},
			"limit": {
				Type:        framework.TypeInt,
				Description: `Optional number of entries to return; defaults to all entries.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathCelRoleList,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"keys": {
								Type:        framework.TypeStringSlice,
								Description: "List of CEL roles",
								Required:    true,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathListCelHelpSyn,
		HelpDescription: pathListCelHelpDesc,
	}
}

func pathCelRole(b *jwtAuthBackend) *framework.Path {
	pathCelRolesResponseFields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "Name of the cel role",
		},
		"auth_program": {
			Type:        framework.TypeString,
			Description: "CEL expression defining the auth program for the role",
		},
		"failure_policy": {
			Type:        framework.TypeString,
			Description: "Failure policy if CEL expressions are not validated",
		},
		"message": {
			Type:        framework.TypeString,
			Description: "Static error message if validation fails",
		},
	}

	return &framework.Path{
		Pattern: "cel/role/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixJWT,
			OperationSuffix: "role",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the cel role",
			},
			"auth_program": {
				Type:        framework.TypeString,
				Description: "CEL expression defining the auth program for the role",
			},
			"failure_policy": {
				Type:        framework.TypeString,
				Description: "Failure policy if CEL expressions are not validated",
			},
			"message": {
				Type:        framework.TypeString,
				Description: "Static error message if validation fails",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCelRoleRead,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields:      pathCelRolesResponseFields,
					}},
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCelRoleCreate,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields:      pathCelRolesResponseFields,
					}},
				},
				// Read more about why these flags are set in backend.go.
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathCelRoleDelete,
				Responses: map[int][]framework.Response{
					http.StatusNoContent: {{
						Description: "No Content",
					}},
				},
				// Read more about why these flags are set in backend.go.
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
			logical.PatchOperation: &framework.PathOperation{
				Callback: b.pathCelRolePatch,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields:      pathCelRolesResponseFields,
					}},
				},
				// Read more about why these flags are set in backend.go.
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},

		HelpSynopsis:    pathCelRoleHelpSyn,
		HelpDescription: pathCelRoleHelpDesc,
	}
}

func (b *jwtAuthBackend) pathCelRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	nameRaw, ok := data.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing required field 'name'"), nil
	}
	name := nameRaw.(string)

	authProgram := ""
	if authProgramRaw, ok := data.GetOk("auth_program"); !ok {
		return logical.ErrorResponse("missing required field 'auth_program'"), nil
	} else {
		authProgram = authProgramRaw.(string)
	}

	failurePolicy := "Deny" // Default value
	if failurePolicyRaw, ok := data.GetOk("failure_policy"); ok {
		failurePolicy = failurePolicyRaw.(string)
		if failurePolicy != "Deny" && failurePolicy != "Modify" {
			return logical.ErrorResponse("failure_policy must be 'Deny' or 'Modify'"), nil
		}
	}

	entry := &celRoleEntry{
		Name:          name,
		AuthProgram:   authProgram,
		FailurePolicy: failurePolicy,
		Message:       data.Get("message").(string),
	}

	resp, err := validateCelRoleCreation(b, entry, ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return resp, nil
	}

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("cel/role/"+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *jwtAuthBackend) pathCelRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)

	entries, err := req.Storage.ListPage(ctx, "cel/role/", after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *jwtAuthBackend) pathCelRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing CEL role name"), nil
	}

	role, err := b.getCelRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: role.ToResponseData(),
	}
	return resp, nil
}

func (b *jwtAuthBackend) pathCelRolePatch(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	txRollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	roleName := data.Get("name").(string)

	oldEntry, err := b.getCelRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if oldEntry == nil {
		return logical.ErrorResponse("Unable to fetch cel role entry to patch"), nil
	}

	entry := &celRoleEntry{
		Name:          roleName,
		AuthProgram:   data.Get("auth_program").(string),
		FailurePolicy: data.Get("failure_policy").(string),
		Message:       data.Get("message").(string),
	}

	resp, err := validateCelRoleCreation(b, entry, ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return resp, nil
	}

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("cel/role/"+roleName, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *jwtAuthBackend) pathCelRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "cel/role/"+data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *jwtAuthBackend) getCelRole(ctx context.Context, s logical.Storage, roleName string) (*celRoleEntry, error) {
	entry, err := s.Get(ctx, "cel/role/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result celRoleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	result.Name = roleName

	return &result, nil
}

func validateCelRoleCreation(b *jwtAuthBackend, entry *celRoleEntry, ctx context.Context, s logical.Storage) (*logical.Response, error) {
	resp := &logical.Response{}

	_, err := b.validateCelExpressions(entry.AuthProgram)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	resp.Data = entry.ToResponseData()
	return resp, nil
}

func (b *jwtAuthBackend) validateCelExpressions(rule string) (bool, error) {
	role := jwtRole{}
	env, err := b.celEnv(&role)
	if err != nil {
		return false, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	ast, issues := env.Compile(rule)
	if issues != nil && issues.Err() != nil {
		return false, fmt.Errorf("Invalid CEL syntax: %v", issues.Err())
	}

	// Check AST for errors
	if ast == nil {
		return false, fmt.Errorf("failed to compile CEL rule")
	}

	return true, nil
}

func (b *jwtAuthBackend) celEnv(role *jwtRole) (*cel.Env, error) {
	return cel.NewEnv(
		// these functions are closures around `role` and can alter it
		cel.Variable("claims", cel.MapType(cel.StringType, cel.DynType)),
		cel.Function("SetPolicies",
			cel.Overload("SetPolicies",
				[]*cel.Type{cel.ListType(types.StringType)},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					list, ok := arg.(traits.Lister)
					if !ok {
						return types.NewErr("expected a list of strings")
					}

					// Iterate over the list
					for i := int64(0); i < int64(list.Size().(types.Int)); i++ {
						elem := fmt.Sprintf("%v", list.Get(types.Int(i)))
						role.TokenPolicies = append(role.TokenPolicies, elem)
					}

					// Return true
					return types.True
				}),
			),
		),
		cel.Function("SetBoundCIDRs",
			cel.Overload("SetBoundCIDRs",
				[]*cel.Type{cel.ListType(types.StringType)},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					list, ok := arg.(traits.Lister)
					if !ok {
						return types.NewErr("expected a list of strings")
					}

					// Iterate over the list
					for i := int64(0); i < int64(list.Size().(types.Int)); i++ {
						elem := fmt.Sprintf("%v", list.Get(types.Int(i)))
						sockAddr, err := sockaddr.NewSockAddr(elem)
						if err != nil {
							return types.NewErr("expected a list of CIDRs")
						}
						role.TokenBoundCIDRs = append(role.TokenBoundCIDRs,
							&sockaddr.SockAddrMarshaler{SockAddr: sockAddr})
					}

					// Return true
					return types.True
				}),
			),
		),
		cel.Function("SetTTL",
			cel.Overload("SetTTL",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					ttl, ok := arg.(types.String)
					if !ok {
						return types.NewErr("expected a duration string")
					}
					duration, err := parseutil.ParseDurationSecond(fmt.Sprintf("%v", ttl))
					if err != nil {
						return types.NewErr("expected a duration string")
					}
					role.TokenTTL = duration
					return types.True
				}),
			),
		),
		cel.Function("SetMaxTTL",
			cel.Overload("SetMaxTTL",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					ttl, ok := arg.(types.String)
					if !ok {
						return types.NewErr("expected a duration string")
					}
					duration, err := parseutil.ParseDurationSecond(fmt.Sprintf("%v", ttl))
					if err != nil {
						return types.NewErr("expected a duration string")
					}
					role.TokenMaxTTL = duration
					return types.True
				}),
			),
		),
		cel.Function("SetExplicitMaxTTL",
			cel.Overload("SetExplicitMaxTTL",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					ttl, ok := arg.(types.String)
					if !ok {
						return types.NewErr("expected a duration string")
					}
					duration, err := parseutil.ParseDurationSecond(fmt.Sprintf("%v", ttl))
					if err != nil {
						return types.NewErr("expected a duration string")
					}
					role.TokenExplicitMaxTTL = duration
					return types.True
				}),
			),
		),
		cel.Function("SetPeriod",
			cel.Overload("SetPeriod",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					ttl, ok := arg.(types.String)
					if !ok {
						return types.NewErr("expected a duration string")
					}
					duration, err := parseutil.ParseDurationSecond(fmt.Sprintf("%v", ttl))
					if err != nil {
						return types.NewErr("expected a duration string")
					}
					role.TokenPeriod = duration
					return types.True
				}),
			),
		),
		cel.Function("SetNoDefaultPolicy",
			cel.Overload("SetNoDefaultPolicy",
				[]*cel.Type{cel.BoolType},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					boolSetting, ok := arg.(types.Bool)
					if !ok {
						return types.NewErr("expected a boolean")
					}
					role.TokenNoDefaultPolicy = boolSetting.Value().(bool)
					return types.True
				}),
			),
		),
		cel.Function("SetStrictlyBindIP",
			cel.Overload("SetStrictlyBindIP",
				[]*cel.Type{cel.BoolType},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					boolSetting, ok := arg.(types.Bool)
					if !ok {
						return types.NewErr("expected a boolean")
					}
					role.TokenStrictlyBindIP = boolSetting.Value().(bool)
					return types.True
				}),
			),
		),
		cel.Function("SetTokenNumUses",
			cel.Overload("SetTokenNumUses",
				[]*cel.Type{cel.IntType},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					intSetting, ok := arg.(types.Int)
					if !ok {
						return types.NewErr("expected an integer")
					}
					role.TokenNumUses = int(intSetting)
					return types.True
				}),
			),
		),
		cel.Function("SetTokenType",
			cel.Overload("SetTokenType",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					strSetting, ok := arg.(types.String)
					if !ok {
						return types.NewErr("expected a string")
					}
					ttype, err := logical.NewTokenType(fmt.Sprintf("%v", strSetting))
					if err != nil {
						return types.NewErr("expected a token type string")
					}
					role.TokenType = ttype
					return types.True
				}),
			),
		),
		cel.Function("SetUserClaim",
			cel.Overload("SetUserClaim",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					strSetting, ok := arg.(types.String)
					if !ok {
						return types.NewErr("expected the user claim field name")
					}
					role.UserClaim = fmt.Sprintf("%v", strSetting)
					return types.True
				}),
			),
		),
	)
}

const (
	pathListCelHelpSyn  = `List the existing CEL roles in this backend`
	pathListCelHelpDesc = `CEL roles will be listed by the role name.`
	pathCelRoleHelpSyn  = `Manage the CEL roles that can be created with this backend.`
	pathCelRoleHelpDesc = `This path lets you manage the CEL roles that can be created with this backend.`
)

func (r *celRoleEntry) ToResponseData() map[string]interface{} {
	return map[string]interface{}{
		"name":           r.Name,
		"auth_program":   r.AuthProgram,
		"failure_policy": r.FailurePolicy,
		"message":        r.Message,
	}
}
