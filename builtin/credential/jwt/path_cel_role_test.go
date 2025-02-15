// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestJwt_CelRoleCreate(t *testing.T) {
	t.Parallel()

	// Test case for creating CEL roles
	type TestCase struct {
		Name          string
		AuthProgram   string
		ExpectErr     bool
		FailurePolicy string
	}

	testCases := []TestCase{
		{
			Name:          "testcelrole_valid",
			AuthProgram:   "1 == 1",
			ExpectErr:     false,
			FailurePolicy: "Modify",
		},
		{
			Name:          "testcelrole_invalid",
			AuthProgram:   "invalid_cel_syntax",
			ExpectErr:     true,
			FailurePolicy: "Modify",
		},
	}

	// Create a backend with storage for testing
	b, storage := getBackend(t)

	for tcNum, tc := range testCases {
		t.Run(tc.Name, func(*testing.T) {
			var resp *logical.Response
			var roleDataResp *logical.Response
			var err error

			// Data for creating the role
			roleData := map[string]interface{}{
				"auth_program": tc.AuthProgram,
			}

			// Add failure_policy only if it's provided in the test case
			if tc.FailurePolicy != "" {
				roleData["failure_policy"] = tc.FailurePolicy
			}

			// Create the CEL role
			roleReq := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "cel/role/" + tc.Name,
				Storage:   storage,
				Data:      roleData,
			}

			resp, err = b.HandleRequest(context.Background(), roleReq)
			updateError := err != nil || (resp != nil && resp.IsError())
			if tc.ExpectErr {
				if !updateError {
					t.Fatalf("expected failure for [%s] but got none", tc.Name)
				}
			} else {
				if updateError {
					t.Fatalf("bad [%d/%s] read: err: %v resp: %#v", tcNum, tc.Name, err, resp)
				}
			}

			// Read back the role to verify
			roleReq.Operation = logical.ReadOperation
			roleDataResp, err = b.HandleRequest(context.Background(), roleReq)
			// if we expected an error above there should be no cel role to read
			found := err == nil && roleDataResp != nil
			if tc.ExpectErr {
				if found {
					t.Fatalf("expected failure for [%s] but got none", tc.Name)
				}
			} else {
				if !found {
					t.Fatalf("bad [%d/%s] read: not found", tcNum, tc.Name)
				}
				// Verify role data in read
				data := roleDataResp.Data
				if data == nil {
					t.Fatalf("bad [%d/%s] read: expected data, got nil", tcNum, tc.Name)
				}

				// Validate fields
				require.Equal(t, tc.Name, data["name"], fmt.Sprintf("bad [%d] name mismatch", tcNum))
				require.Equal(t, tc.AuthProgram, data["auth_program"], fmt.Sprintf("bad [%d] auth_program mismatch", tcNum))
			}

			// List roles to verify
			roleReq.Path = "cel/role"
			roleReq.Operation = logical.ListOperation
			roleListResp, err := b.HandleRequest(context.Background(), roleReq)
			foundRoleInList := roleListResp != nil && slices.Contains(roleListResp.Data["keys"].([]string), tc.Name)
			if tc.ExpectErr {
				if foundRoleInList {
					t.Fatalf("expected not to find [%s] in cel roles list", tc.Name)
				}
			} else {
				if !foundRoleInList {
					t.Fatalf("bad [%d/%s] read: cel role not found", tcNum, tc.Name)
				}
			}
		})
	}
}
