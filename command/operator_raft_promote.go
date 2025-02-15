// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"fmt"
	"strings"

	"github.com/hashicorp/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*OperatorRaftPromoteCommand)(nil)
	_ cli.CommandAutocomplete = (*OperatorRaftPromoteCommand)(nil)
)

type OperatorRaftPromoteCommand struct {
	*BaseCommand
}

func (c *OperatorRaftPromoteCommand) Synopsis() string {
	return "Promotes a permanent non-voter to a voter"
}

func (c *OperatorRaftPromoteCommand) Help() string {
	helpText := `
Usage: bao operator raft promote <server_id>

  Promotes a permanent non-voter to a voter.

	  $ bao operator raft promote node1

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *OperatorRaftPromoteCommand) Flags() *FlagSets {
	return c.flagSet(FlagSetHTTP | FlagSetOutputFormat)
}

func (c *OperatorRaftPromoteCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *OperatorRaftPromoteCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *OperatorRaftPromoteCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	serverID := ""

	args = f.Args()
	switch len(args) {
	case 1:
		serverID = strings.TrimSpace(args[0])
	default:
		c.UI.Error(fmt.Sprintf("Incorrect arguments (expected 1, got %d)", len(args)))
		return 1
	}

	if len(serverID) == 0 {
		c.UI.Error("Server id is required")
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	_, err = client.Logical().Write("sys/storage/raft/promote", map[string]interface{}{
		"server_id": serverID,
	})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error promoting server: %s", err))
		return 2
	}

	c.UI.Output("Server promoted successfully!")

	return 0
}
