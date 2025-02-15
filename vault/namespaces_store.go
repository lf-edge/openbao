// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (c *Core) NamespaceByID(ctx context.Context, nsID string) (*namespace.Namespace, error) {
	return namespaceByID(ctx, nsID, c)
}

func (c *Core) ListNamespaces(includePath bool) []*namespace.Namespace {
	return []*namespace.Namespace{namespace.RootNamespace}
}

func (c *Core) resetNamespaceCache() {}

// start all new namespace code below

var immutableNamespaces = []string{
	"sys",
	"audit",
	"auth",
	"cubbyhole",
	"identity",
}

// NamespaceStore is used to provide durable storage of namespace
type NamespaceStore struct {
	core    *Core
	aclView BarrierView

	// This is used to ensure that writes to the store (acl) or to the egp
	// path tree don't happen concurrently. We are okay reading stale data so
	// long as there aren't concurrent writes.
	modifyLock *sync.RWMutex

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NamespaceEntry is used to store a namespace by name
type NamespaceEntry struct {
	namespace.Namespace
}

// NewNamespaceStore creates a new NamespaceStore that is backed
// using a given view. It used used to durable store and manage named namespace.
func NewNamespaceStore(ctx context.Context, core *Core, baseView BarrierView, logger hclog.Logger) (*NamespaceStore, error) {
	ns := &NamespaceStore{
		aclView:    baseView.SubView(namespaceSubPath),
		modifyLock: new(sync.RWMutex),
		logger:     logger,
		core:       core,
	}

	// initialize the namespace store to have the root namespace
	err := ns.SetNamespace(ctx, namespace.RootNamespaceID, map[string]string{}, true)
	return ns, err
}

// setupNamespaceStore is used to initialize the namespace store
// when the vault is being unsealed.
func (c *Core) setupNamespaceStore(ctx context.Context) error {
	// Create the Namespace store
	var err error
	nsLogger := c.baseLogger.Named("namespace")
	c.AddLogger(nsLogger)
	c.namespaceStore, err = NewNamespaceStore(ctx, c, c.systemBarrierView, nsLogger)

	return err
}

// teardownNamespaceStore is used to reverse setupNamespaceStore
// when the vault is being sealed.
func (c *Core) teardownNamespaceStore() error {
	c.namespaceStore = nil
	return nil
}

func (ns *NamespaceStore) invalidate(ctx context.Context, path string) error {
	if err := ns.DeleteNamespace(ctx, path); err != nil {
		return err
	}

	ns = nil
	return nil
}

func (ns *NamespaceStore) getStorageView(ctx context.Context) (BarrierView, error) {
	s, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	view := NewBarrierView(ns.aclView, s.Path)
	if view == nil {
		return nil, fmt.Errorf("unable to get the barrier subview for namespace")
	}
	return view, nil
}

// SetNamespace is used to create or update a given namespace
func (ns *NamespaceStore) SetNamespace(ctx context.Context, path string, meta map[string]string, init ...bool) error {
	defer metrics.MeasureSince([]string{"namespace", "set_namespace"}, time.Now())

	if path == "" {
		return fmt.Errorf("path name missing")
	}

	// Namespaces are normalized to lower-case
	path = ns.sanitizeName(path)
	if strutil.StrListContains(immutableNamespaces, path) || strings.Contains(path, "/") {
		return fmt.Errorf("cannot update %q namespace", path)
	}

	ns.modifyLock.Lock()
	defer ns.modifyLock.Unlock()

	// Get the appropriate view
	view, err := ns.getStorageView(ctx)
	if err != nil || view == nil {
		return fmt.Errorf("unable to get the barrier subview for namespace: %v", err)
	}

	if init == nil && path == namespace.RootNamespaceID {
		return fmt.Errorf(`cannot update "root" namespace`)
	}

	// Create the entry
	entry, err := logical.StorageEntryJSON(path, &namespace.Namespace{
		ID:             path,
		CustomMetadata: meta,
	})
	if err != nil {
		return fmt.Errorf("failed to create entry for namespace: %w", err)
	}

	if err := view.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to put new namespace to %s: %w", path, err)
	}

	return nil
}

// PatchNamespace is used to update the given namespace
func (ns *NamespaceStore) PatchNamespace(ctx context.Context, path string, meta map[string]string) error {
	return fmt.Errorf("namespace patching is not supported, use the delete and set operation instead")
}

// GetNamespace is used to fetch the named namespace
func (ns *NamespaceStore) GetNamespace(ctx context.Context, name string) (*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace"}, time.Now())

	// Namespaces are normalized to lower-case
	name = ns.sanitizeName(name)
	// Get the appropriate view
	view, err := ns.getStorageView(ctx)
	if err != nil || view == nil {
		return nil, fmt.Errorf("unable to get the barrier subview for namespace: %v", err)
	}

	out, err := view.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to read namespace: %w", err)
	}
	if out == nil {
		return nil, nil
	}
	namespaceEntry := new(namespace.Namespace)
	err = out.DecodeJSON(namespaceEntry)

	return namespaceEntry, err
}

// ListNamespaces is used to list the available namespaces
func (ns *NamespaceStore) ListNamespaces(ctx context.Context) ([]string, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespaces"}, time.Now())

	// Get the appropriate view
	view, err := ns.getStorageView(ctx)
	if err != nil || view == nil {
		return nil, fmt.Errorf("unable to get the barrier subview for namespace: %v", err)
	}

	return logical.CollectKeys(ctx, view)
}

// DeleteNamespace is used to delete the named namespace
func (ns *NamespaceStore) DeleteNamespace(ctx context.Context, path string) error {
	defer metrics.MeasureSince([]string{"namespace", "delete_namespace"}, time.Now())

	ns.modifyLock.Lock()
	defer ns.modifyLock.Unlock()

	// Namespaces are normalized to lower-case
	path = ns.sanitizeName(path)
	view, err := ns.getStorageView(ctx)
	if err != nil || view == nil {
		return fmt.Errorf("unable to get the barrier subview for namespace: %v", err)
	}

	if strutil.StrListContains(immutableNamespaces, path) || strings.Contains(path, "/") {
		return fmt.Errorf("cannot delete %q namespace", path)
	}

	if path == namespace.RootNamespaceID {
		return fmt.Errorf(`cannot delete "root" namespace`)
	}

	if err := view.Delete(ctx, path); err != nil {
		return fmt.Errorf("failed to delete namespace: %w", err)
	}

	return nil
}

func (ns *NamespaceStore) sanitizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
