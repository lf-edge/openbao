// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/cel-go/cel"
	"github.com/mitchellh/mapstructure"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type celRoleEntry struct {
	Name              string            `json:"name"`                     // Required
	ValidationProgram ValidationProgram `json:"validation_program"`       // Required
	FailurePolicy     string            `json:"failure_policy,omitempty"` // Defaults to "Deny"
	Message           string            `json:"message,omitempty"`
}

type ValidationProgram struct {
	Variables         map[string]string `json:"variables,omitempty"`
	Expressions       string            `json:"expressions"` // Required
	MessageExpression string            `json:"message_expressions,omitempty"`
}

func pathListCelRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "cel/roles/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationSuffix: "cel",
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
				Callback: b.pathCelList,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"keys": {
								Type:        framework.TypeStringSlice,
								Description: "List of cel roles",
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

func pathCelRoles(b *backend) *framework.Path {
	pathCelRolesResponseFields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "Name of the cel role",
		},
		"validation_program": {
			Type:        framework.TypeMap,
			Description: "CEL rules defining the validation program for the role",
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
		Pattern: "cel/roles/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationSuffix: "role",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the cel role",
			},
			"validation_program": {
				Type:        framework.TypeMap,
				Description: "CEL rules defining the validation program for the role",
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

func (b *backend) pathCelRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	nameRaw, ok := data.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing required field 'name'"), nil
	}
	name := nameRaw.(string)

	validationProgram := ValidationProgram{}
	if validationProgramRaw, ok := data.GetOk("validation_program"); !ok {
		return logical.ErrorResponse("missing required field 'validation_program'"), nil
		// Ensure "validation_program" is a map
	} else if validationProgramMap, ok := validationProgramRaw.(map[string]interface{}); !ok {
		return logical.ErrorResponse("'validation_program' must be a valid map"), nil

		// Decode "validation_program" into the ValidationProgram struct
	} else if err := mapstructure.Decode(validationProgramMap, &validationProgram); err != nil {
		return logical.ErrorResponse("failed to decode 'validation_program': %v", err), nil
	}

	failurePolicy := "Deny" // Default value
	if failurePolicyRaw, ok := data.GetOk("failure_policy"); ok {
		failurePolicy = failurePolicyRaw.(string)
		if failurePolicy != "Deny" && failurePolicy != "Modify" {
			return logical.ErrorResponse("failure_policy must be 'Deny' or 'Modify'"), nil
		}
	}

	entry := &celRoleEntry{
		Name:              name,
		ValidationProgram: validationProgram,
		FailurePolicy:     failurePolicy,
		Message:           data.Get("message").(string),
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

func (b *backend) pathCelList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)

	entries, err := req.Storage.ListPage(ctx, "cel/roles/", after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathCelRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

func (b *backend) pathCelRolePatch(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	oldEntry, err := b.getCelRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if oldEntry == nil {
		return logical.ErrorResponse("Unable to fetch cel role entry to patch"), nil
	}

	entry := &celRoleEntry{
		Name:              roleName,
		ValidationProgram: data.Get("validation_program").(ValidationProgram),
		FailurePolicy:     data.Get("failure_policy").(string),
		Message:           data.Get("message").(string),
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

	return resp, nil
}

func (b *backend) pathCelRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "cel/role/"+data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) getCelRole(ctx context.Context, s logical.Storage, roleName string) (*celRoleEntry, error) {
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

func validateCelRoleCreation(b *backend, entry *celRoleEntry, ctx context.Context, s logical.Storage) (*logical.Response, error) {
	resp := &logical.Response{}

	_, err := validateCelExpressions(entry.ValidationProgram.Expressions)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	resp.Data = entry.ToResponseData()
	return resp, nil
}

func validateCelExpressions(rule string) (bool, error) {
	env, err := cel.NewEnv()
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

const (
	pathListCelHelpSyn  = `List the existing CEL roles in this backend`
	pathListCelHelpDesc = `CEL policies will be listed by the role name.`
	pathCelRoleHelpSyn  = `Manage the cel roles that can be created with this backend.`
	pathCelRoleHelpDesc = `This path lets you manage the cel roles that can be created with this backend.`
)

func (r *celRoleEntry) ToResponseData() map[string]interface{} {
	return map[string]interface{}{
		"name":               r.Name,
		"validation_program": r.ValidationProgram,
		"failure_policy":     r.FailurePolicy,
		"message":            r.Message,
	}
}
