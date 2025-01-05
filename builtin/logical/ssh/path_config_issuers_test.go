package ssh

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestSSH_ConfigIssuers(t *testing.T) {
	// create backend config
	config := logical.TestBackendConfig()
	// NOTE (gabrielopesantos): Is this part needed?
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Cannot create backend: %s", err)
	}

	// reading the 'default' configured issuer when no default has been set should return a 200 with an empty 'default' issuer
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/issuers",
		Storage:   config.StorageView,
	})

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot fetch 'default' issuer: err: %v, resp: %v", err, resp)
	}

	// check if the 'default' keyword exists and the value is an empty string
	if resp.Data["default"] != issuerID("") {
		t.Fatalf("expected an empty string but got '%v'", resp.Data["default"])
	}

	// submit a 'default' issuer with 'config/ca' endpoint
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/ca",
		Storage:   config.StorageView,
		Data: map[string]interface{}{
			"generate_signing_key": true,
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot submit CA issuer as default: err: %v, resp: %v", err, resp)
	}

	// parse 'default' issuer's id
	defaultIssuerId := resp.Data["issuer_id"].(issuerID)

	// read the 'default' issuer
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/issuers",
		Storage:   config.StorageView,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot read default issuer: err: %v, resp: %v", err, resp)
	}

	// check if the 'default' keyword exists and the value is the same as the 'default' issuer's id
	if resp.Data["default"] != defaultIssuerId {
		t.Fatalf("expected '%v' but got '%v'", defaultIssuerId, resp.Data["default"])
	}

	// submit a new issuer
	issuerName := "test-issuer"
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issuers/import/" + issuerName,
		Storage:   config.StorageView,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot submit new issuer: err: %v, resp: %v", err, resp)
	}

	// parse 'test-issuer's id
	testIssuerId := resp.Data["issuer_id"].(issuerID)

	// set 'test-issuer' as the 'default' issuer
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/issuers",
		Data: map[string]interface{}{
			"default": issuerName,
		},
		Storage: config.StorageView,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot set 'test-issuer' as default: err: %v, resp: %v", err, resp)
	}

	// read the 'default' issuer and check if it's the same as 'test-issuer'
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/issuers",
		Storage:   config.StorageView,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("cannot read default issuer: err: %v, resp: %v", err, resp)
	}

	if resp.Data["default"] != testIssuerId {
		t.Fatalf("expected '%v' but got '%v'", issuerName, resp.Data["default"])
	}
}
