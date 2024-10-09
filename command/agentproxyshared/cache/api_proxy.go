// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cache

import (
	"context"
	"fmt"
	gohttp "net/http"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
)

// APIProxy is an implementation of the proxier interface that is used to
// forward the request to Vault and get the response.
type APIProxy struct {
	client                  *api.Client
	logger                  hclog.Logger
	userAgentString         string
	userAgentStringFunction func(string) string
}

var _ Proxier = &APIProxy{}

type APIProxyConfig struct {
	Client *api.Client
	Logger hclog.Logger
	// UserAgentString is used as the User Agent when the proxied client
	// does not have a user agent of its own.
	UserAgentString string
	// UserAgentStringFunction is the function to transform the proxied client's
	// user agent into one that includes Vault-specific information.
	UserAgentStringFunction func(string) string
}

func NewAPIProxy(config *APIProxyConfig) (Proxier, error) {
	if config.Client == nil {
		return nil, fmt.Errorf("nil API client")
	}
	return &APIProxy{
		client:                  config.Client,
		logger:                  config.Logger,
		userAgentString:         config.UserAgentString,
		userAgentStringFunction: config.UserAgentStringFunction,
	}, nil
}

func (ap *APIProxy) Send(ctx context.Context, req *SendRequest) (*SendResponse, error) {
	client, err := ap.client.Clone()
	if err != nil {
		return nil, err
	}
	client.SetToken(req.Token)

	// Derive and set a logger for the client
	clientLogger := ap.logger.Named("client")
	client.SetLogger(clientLogger)

	// http.Transport will transparently request gzip and decompress the response, but only if
	// the client doesn't manually set the header. Removing any Accept-Encoding header allows the
	// transparent compression to occur.
	req.Request.Header.Del("Accept-Encoding")

	if req.Request.Header == nil {
		req.Request.Header = make(gohttp.Header)
	}

	// Set our User-Agent to be one indicating we are Vault Agent's API proxy.
	// If the sending client had one, preserve it.
	if req.Request.Header.Get("User-Agent") != "" {
		initialUserAgent := req.Request.Header.Get("User-Agent")
		req.Request.Header.Set("User-Agent", ap.userAgentStringFunction(initialUserAgent))
	} else {
		req.Request.Header.Set("User-Agent", ap.userAgentString)
	}

	client.SetHeaders(req.Request.Header)

	fwReq := client.NewRequest(req.Request.Method, req.Request.URL.Path)
	fwReq.BodyBytes = req.RequestBody

	query := req.Request.URL.Query()
	if len(query) != 0 {
		fwReq.Params = query
	}

	// Make the request to Vault and get the response
	ap.logger.Info("forwarding request to OpenBao", "method", req.Request.Method, "path", req.Request.URL.Path)

	resp, err := client.RawRequestWithContext(ctx, fwReq)
	if resp == nil && err != nil {
		// We don't want to cache nil responses, so we simply return the error
		return nil, err
	}

	// Before error checking from the request call, we'd want to initialize a SendResponse to
	// potentially return
	sendResponse, newErr := NewSendResponse(resp, nil)
	if newErr != nil {
		return nil, newErr
	}

	// Bubble back the api.Response as well for error checking/handling at the handler layer.
	return sendResponse, err
}
