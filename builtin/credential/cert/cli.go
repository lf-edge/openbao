// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/openbao/openbao/api/v2"
)

type CLIHandler struct{}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string, nonInteractive bool) (*api.Secret, error) {
	var data struct {
		Mount string `mapstructure:"mount"`
		Name  string `mapstructure:"name"`
	}
	if err := mapstructure.WeakDecode(m, &data); err != nil {
		return nil, err
	}

	if data.Mount == "" {
		data.Mount = "cert"
	}

	options := map[string]interface{}{
		"name": data.Name,
	}
	path := fmt.Sprintf("auth/%s/login", data.Mount)
	secret, err := c.Logical().Write(path, options)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("empty response from credential provider")
	}

	return secret, nil
}

func (h *CLIHandler) Help() string {
	help := `
Usage: bao login -method=cert [CONFIG K=V...]

  The certificate auth method allows users to authenticate with a
  client certificate passed with the request. The -client-cert and -client-key
  flags are included with the "bao login" command, NOT as configuration to the
  auth method.

  Authenticate using a local client certificate:

      $ bao login -method=cert -client-cert=cert.pem -client-key=key.pem

Configuration:

  name=<string>
      Certificate role to authenticate against.
`

	return strings.TrimSpace(help)
}
