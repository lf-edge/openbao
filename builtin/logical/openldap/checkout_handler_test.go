// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package openldap

import (
	"context"
	"reflect"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestCheckOutHandlerStorageLayer(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)

	checkOut := &CheckOut{
		BorrowerEntityID:    "entity-id",
		BorrowerClientToken: "client-token",
	}
	serviceAccountName := "becca@example.com"

	config := &config{
		PasswordLength: 14,
	}
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	// Service accounts must initially be checked in to the library
	if err := b.CheckIn(ctx, s, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	// If we try to check something out for the first time, it should succeed.
	if err := b.CheckOut(ctx, s, serviceAccountName, checkOut); err != nil {
		t.Fatal(err)
	}

	// We should have the testCheckOut in storage now.
	storedCheckOut, err := b.LoadCheckOut(ctx, s, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if storedCheckOut == nil {
		t.Fatal("storedCheckOut should not be nil")
	}
	if !reflect.DeepEqual(checkOut, storedCheckOut) {
		t.Fatalf(`expected %+v to be equal to %+v`, checkOut, storedCheckOut)
	}

	// If we try to check something out that's already checked out, we should
	// get a CurrentlyCheckedOutErr.
	if err := b.CheckOut(ctx, s, serviceAccountName, checkOut); err == nil {
		t.Fatal("expected err but received none")
	} else if err != errCheckedOut {
		t.Fatalf("expected errCheckedOut, but received %s", err)
	}

	// If we try to check something in, it should succeed.
	if err := b.CheckIn(ctx, s, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	// We should no longer have the testCheckOut in s.
	storedCheckOut, err = b.LoadCheckOut(ctx, s, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if !storedCheckOut.IsAvailable {
		t.Fatal("storedCheckOut should be nil")
	}

	// If we try to check it in again, it should have the same behavior.
	if err := b.CheckIn(ctx, s, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	// If we check it out again, it should succeed.
	if err := b.CheckOut(ctx, s, serviceAccountName, checkOut); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordHandlerInterfaceFulfillment(t *testing.T) {
	ctx := context.Background()
	b, s := getBackend(false)
	defer b.Cleanup(ctx)

	checkOut := &CheckOut{
		BorrowerEntityID:    "entity-id",
		BorrowerClientToken: "client-token",
	}
	serviceAccountName := "becca@example.com"

	config := &config{
		PasswordLength: 14,
	}
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		panic(err)
	}
	if err := s.Put(ctx, entry); err != nil {
		panic(err)
	}

	// We must always start managing a service account by checking it in.
	if err := b.CheckIn(ctx, s, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	// There should be no error during check-out.
	if err := b.CheckOut(ctx, s, serviceAccountName, checkOut); err != nil {
		t.Fatal(err)
	}

	// The password should get rotated successfully during check-in.
	origPassword, err := retrievePassword(ctx, s, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.CheckIn(ctx, s, serviceAccountName); err != nil {
		t.Fatal(err)
	}
	currPassword, err := retrievePassword(ctx, s, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if currPassword == "" || currPassword == origPassword {
		t.Fatal("expected password, but received none")
	}

	// There should be no error during delete and the password should be deleted.
	if err := b.DeleteCheckout(ctx, s, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	currPassword, err = retrievePassword(ctx, s, serviceAccountName)
	if err != errNotFound {
		t.Fatal("expected errNotFound")
	}

	checkOut, err = b.LoadCheckOut(ctx, s, serviceAccountName)
	if err != errNotFound {
		t.Fatal("expected err not found")
	}
	if checkOut != nil {
		t.Fatal("expected checkOut to be nil")
	}
}
