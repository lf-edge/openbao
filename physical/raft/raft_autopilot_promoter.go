// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"time"

	"github.com/hashicorp/raft"
	autopilot "github.com/hashicorp/raft-autopilot"
)

// Ensure that the CustomPromoter implements the autopilot.Promoter interface
var _ autopilot.Promoter = (*CustomPromoter)(nil)

type CustomPromoter struct {
	autopilot.StablePromoter
}

// GetNodeTypes will return a map of node types for each server in the cluster. This particular interface implementation
// will mark all servers as voters except for those that are marked as non-voters in the configuration.
func (_ *CustomPromoter) GetNodeTypes(c *autopilot.Config, s *autopilot.State) map[raft.ServerID]autopilot.NodeType {
	types := make(map[raft.ServerID]autopilot.NodeType)
	nonVoters := c.Ext.(map[raft.ServerID]bool)
	for id := range s.Servers {
		// If the server is a non-voter, mark it as such
		if _, ok := nonVoters[id]; ok {
			types[id] = NodeNonVoter
		} else {
			types[id] = autopilot.NodeVoter
		}
	}
	return types
}

// CalculatePromotionsAndDemotions will return a list of all promotions and demotions to be done as well as the server id of
// the desired leader. This particular interface implementation maintains a stable leader and will promote healthy servers
// to voting status if they are not marked as permanent non-voters. It will never change the leader ID nor will it perform demotions.
func (_ *CustomPromoter) CalculatePromotionsAndDemotions(c *autopilot.Config, s *autopilot.State) autopilot.RaftChanges {
	var changes autopilot.RaftChanges

	now := time.Now()
	minStableDuration := s.ServerStabilizationTime(c)
	nonVoters := c.Ext.(map[raft.ServerID]bool)
	for id, server := range s.Servers {
		if _, ok := nonVoters[id]; ok {
			// If the server is marked as a non-voter, demote it
			if server.State == autopilot.RaftVoter {
				changes.Demotions = append(changes.Demotions, id)
			} else {
				// If the server is already a non-voter, skip it
				continue
			}
		}
		// If the server is healthy and stable, promote it to a voter
		if server.State == autopilot.RaftNonVoter && server.Health.IsStable(now, minStableDuration) {
			changes.Promotions = append(changes.Promotions, id)
		}
	}

	return changes
}
