// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	pwd "github.com/hashicorp/go-secure-stdlib/password"
	"github.com/openbao/openbao/api/v2"
)

type CLIHandler struct {
	DefaultMount string
}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string, nonInteractive bool) (*api.Secret, error) {
	var data struct {
		Username string `mapstructure:"username"`
		Password string `mapstructure:"password"`
		Mount    string `mapstructure:"mount"`
	}
	if err := mapstructure.WeakDecode(m, &data); err != nil {
		return nil, err
	}

	if data.Username == "" {
		return nil, fmt.Errorf("'username' must be specified")
	}
	if data.Password == "" {
		if nonInteractive {
			return nil, fmt.Errorf("'password' must be specified and refusing to pull from stdin")
		}

		fmt.Fprintf(os.Stderr, "Password (will be hidden): ")
		password, err := pwd.Read(os.Stdin)
		fmt.Fprintf(os.Stderr, "\n")
		if err != nil {
			return nil, err
		}
		data.Password = password
	}
	if data.Mount == "" {
		data.Mount = h.DefaultMount
	}

	options := map[string]interface{}{
		"password": data.Password,
	}

	path := fmt.Sprintf("auth/%s/login/%s", data.Mount, data.Username)
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
Usage: bao login -method=userpass [CONFIG K=V...]

  The userpass auth method allows users to authenticate using Vault's
  internal user database.

  Authenticate as "sally":

      $ bao login -method=userpass username=sally
      Password (will be hidden):

  Authenticate as "bob":

      $ bao login -method=userpass username=bob password=password

Configuration:

  password=<string>
      Password to use for authentication. If not provided, the CLI will prompt
      for this on stdin.

  username=<string>
      Username to use for authentication.
`

	return strings.TrimSpace(help)
}
