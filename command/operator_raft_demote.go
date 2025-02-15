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
	_ cli.Command             = (*OperatorRaftDemoteCommand)(nil)
	_ cli.CommandAutocomplete = (*OperatorRaftDemoteCommand)(nil)
)

type OperatorRaftDemoteCommand struct {
	*BaseCommand
}

func (c *OperatorRaftDemoteCommand) Synopsis() string {
	return "Demotes a voter to a permanent non-voter"
}

func (c *OperatorRaftDemoteCommand) Help() string {
	helpText := `
Usage: bao operator raft demote <server_id>

  Demotes voter to a permanent non-voter.

	  $ bao operator raft demote node1

` + c.Flags().Help()

	return strings.TrimSpace(helpText)
}

func (c *OperatorRaftDemoteCommand) Flags() *FlagSets {
	return c.flagSet(FlagSetHTTP | FlagSetOutputFormat)
}

func (c *OperatorRaftDemoteCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *OperatorRaftDemoteCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *OperatorRaftDemoteCommand) Run(args []string) int {
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

	_, err = client.Logical().Write("sys/storage/raft/demote", map[string]interface{}{
		"server_id": serverID,
	})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error promoting server: %s", err))
		return 2
	}

	c.UI.Output("Server demoted successfully!")

	return 0
}
