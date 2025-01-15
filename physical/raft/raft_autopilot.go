// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package raft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/raft"
	autopilot "github.com/hashicorp/raft-autopilot"
	"github.com/openbao/openbao/api/v2"
	"go.uber.org/atomic"
)

type CleanupDeadServersValue int

const (
	CleanupDeadServersUnset CleanupDeadServersValue = 0
	CleanupDeadServersTrue  CleanupDeadServersValue = 1
	CleanupDeadServersFalse CleanupDeadServersValue = 2

	// NonVoterPath is the path to the non-voters in the storage.
	NonVoterPath = "autopilot/non-voters"
)

func (c CleanupDeadServersValue) Value() bool {
	switch c {
	case CleanupDeadServersTrue:
		return true
	default:
		return false
	}
}

// AutopilotConfig is used for querying/setting the Autopilot configuration.
type AutopilotConfig struct {
	// CleanupDeadServers controls whether to remove dead servers from the Raft
	// peer list periodically or when a new server joins.
	CleanupDeadServers bool `mapstructure:"cleanup_dead_servers"`

	// CleanupDeadServersValue is used to shadow the CleanupDeadServers field in
	// storage. Having it as an int helps in knowing if the value was set explicitly
	// using the API or not.
	CleanupDeadServersValue CleanupDeadServersValue `mapstructure:"cleanup_dead_servers_value"`

	// LastContactThreshold is the limit on the amount of time a server can go
	// without leader contact before being considered unhealthy.
	LastContactThreshold time.Duration `mapstructure:"-"`

	// DeadServerLastContactThreshold is the limit on the amount of time a server
	// can go without leader contact before being considered failed. This takes
	// effect only when CleanupDeadServers is set.
	DeadServerLastContactThreshold time.Duration `mapstructure:"-"`

	// MaxTrailingLogs is the amount of entries in the Raft Log that a server can
	// be behind before being considered unhealthy.
	MaxTrailingLogs uint64 `mapstructure:"max_trailing_logs"`

	// MinQuorum sets the minimum number of servers allowed in a cluster before
	// autopilot can prune dead servers.
	MinQuorum uint `mapstructure:"min_quorum"`

	// ServerStabilizationTime is the minimum amount of time a server must be in a
	// stable, healthy state before it can be added to the cluster. Only applicable
	// with Raft protocol version 3 or higher.
	ServerStabilizationTime time.Duration `mapstructure:"-"`
}

// Merge combines the supplied config with the receiver. Supplied ones take
// priority.
func (to *AutopilotConfig) Merge(from *AutopilotConfig) {
	if from == nil {
		return
	}
	if from.CleanupDeadServersValue != CleanupDeadServersUnset {
		to.CleanupDeadServers = from.CleanupDeadServersValue.Value()
	}
	if from.MinQuorum != 0 {
		to.MinQuorum = from.MinQuorum
	}
	if from.LastContactThreshold != 0 {
		to.LastContactThreshold = from.LastContactThreshold
	}
	if from.DeadServerLastContactThreshold != 0 {
		to.DeadServerLastContactThreshold = from.DeadServerLastContactThreshold
	}
	if from.MaxTrailingLogs != 0 {
		to.MaxTrailingLogs = from.MaxTrailingLogs
	}
	if from.ServerStabilizationTime != 0 {
		to.ServerStabilizationTime = from.ServerStabilizationTime
	}
}

// Clone returns a duplicate instance of AutopilotConfig with the exact same values.
func (ac *AutopilotConfig) Clone() *AutopilotConfig {
	if ac == nil {
		return nil
	}
	return &AutopilotConfig{
		CleanupDeadServers:             ac.CleanupDeadServers,
		LastContactThreshold:           ac.LastContactThreshold,
		DeadServerLastContactThreshold: ac.DeadServerLastContactThreshold,
		MaxTrailingLogs:                ac.MaxTrailingLogs,
		MinQuorum:                      ac.MinQuorum,
		ServerStabilizationTime:        ac.ServerStabilizationTime,
	}
}

// MarshalJSON makes the autopilot config fields JSON compatible
func (ac *AutopilotConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"cleanup_dead_servers":               ac.CleanupDeadServers,
		"cleanup_dead_servers_value":         ac.CleanupDeadServersValue,
		"last_contact_threshold":             ac.LastContactThreshold.String(),
		"dead_server_last_contact_threshold": ac.DeadServerLastContactThreshold.String(),
		"max_trailing_logs":                  ac.MaxTrailingLogs,
		"min_quorum":                         ac.MinQuorum,
		"server_stabilization_time":          ac.ServerStabilizationTime.String(),
	})
}

// UnmarshalJSON parses the autopilot config JSON blob
func (ac *AutopilotConfig) UnmarshalJSON(b []byte) error {
	var data interface{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	conf := data.(map[string]interface{})
	if err = mapstructure.WeakDecode(conf, ac); err != nil {
		return err
	}
	if ac.LastContactThreshold, err = parseutil.ParseDurationSecond(conf["last_contact_threshold"]); err != nil {
		return err
	}
	if ac.DeadServerLastContactThreshold, err = parseutil.ParseDurationSecond(conf["dead_server_last_contact_threshold"]); err != nil {
		return err
	}
	if ac.ServerStabilizationTime, err = parseutil.ParseDurationSecond(conf["server_stabilization_time"]); err != nil {
		return err
	}

	return nil
}

// FollowerState represents the information about peer that the leader tracks.
type FollowerState struct {
	AppliedIndex    uint64
	LastHeartbeat   time.Time
	LastTerm        uint64
	IsDead          *atomic.Bool
	DesiredSuffrage string
	Version         string
	UpgradeVersion  string
}

// EchoRequestUpdate is here to avoid 1) the list of arguments to Update() getting huge 2) an import cycle on the vault package
type EchoRequestUpdate struct {
	NodeID          string
	AppliedIndex    uint64
	Term            uint64
	DesiredSuffrage string
	UpgradeVersion  string
	SDKVersion      string
}

// FollowerStates holds information about all the followers in the raft cluster
// tracked by the leader.
type FollowerStates struct {
	l         sync.RWMutex
	followers map[string]*FollowerState
}

// NewFollowerStates creates a new FollowerStates object
func NewFollowerStates() *FollowerStates {
	return &FollowerStates{
		followers: make(map[string]*FollowerState),
	}
}

// Update the peer information in the follower states. Note that this function
// runs on the active node. Returns true if a new entry was added, as opposed
// to modifying one already present.
func (s *FollowerStates) Update(req *EchoRequestUpdate) bool {
	s.l.Lock()
	defer s.l.Unlock()

	state, present := s.followers[req.NodeID]
	if !present {
		state = &FollowerState{
			IsDead: atomic.NewBool(false),
		}
		s.followers[req.NodeID] = state
	}

	state.IsDead.Store(false)
	state.AppliedIndex = req.AppliedIndex
	state.LastTerm = req.Term
	state.DesiredSuffrage = req.DesiredSuffrage
	state.LastHeartbeat = time.Now()
	state.Version = req.SDKVersion
	state.UpgradeVersion = req.UpgradeVersion

	return !present
}

// Clear wipes all the information regarding peers in the follower states.
func (s *FollowerStates) Clear() {
	s.l.Lock()
	for i := range s.followers {
		delete(s.followers, i)
	}
	s.l.Unlock()
}

// Delete the entry of a peer represented by the nodeID from follower states.
func (s *FollowerStates) Delete(nodeID string) {
	s.l.Lock()
	delete(s.followers, nodeID)
	s.l.Unlock()
}

// MinIndex returns the minimum raft index applied in the raft cluster.
func (s *FollowerStates) MinIndex() uint64 {
	var min uint64 = math.MaxUint64
	minFunc := func(a, b uint64) uint64 {
		if a > b {
			return b
		}
		return a
	}

	s.l.RLock()
	for _, state := range s.followers {
		min = minFunc(min, state.AppliedIndex)
	}
	s.l.RUnlock()

	if min == math.MaxUint64 {
		return 0
	}

	return min
}

// SetFollowerStates sets the followerStates field in the backend to track peers
// in the raft cluster.
func (b *RaftBackend) SetFollowerStates(states *FollowerStates) {
	b.l.Lock()
	b.followerStates = states
	b.l.Unlock()
}

// SetAutopilotConfig updates the autopilot configuration in the backend.
func (b *RaftBackend) SetAutopilotConfig(config *AutopilotConfig) {
	b.l.Lock()
	b.autopilotConfig = config
	b.logger.Info("updated autopilot configuration", "config", b.autopilotConfig)
	b.l.Unlock()
}

// AutopilotConfig returns the autopilot configuration in the backend.
func (b *RaftBackend) AutopilotConfig() *AutopilotConfig {
	b.l.RLock()
	defer b.l.RUnlock()
	return b.autopilotConfig.Clone()
}

func (b *RaftBackend) defaultAutopilotConfig() *AutopilotConfig {
	return &AutopilotConfig{
		CleanupDeadServers:             false,
		LastContactThreshold:           10 * time.Second,
		DeadServerLastContactThreshold: 24 * time.Hour,
		MaxTrailingLogs:                1000,
		ServerStabilizationTime:        10 * time.Second,
	}
}

func (b *RaftBackend) AutopilotDisabled() bool {
	b.l.RLock()
	disabled := b.disableAutopilot
	b.l.RUnlock()
	return disabled
}

func (b *RaftBackend) startFollowerHeartbeatTracker() {
	b.l.RLock()
	tickerCh := b.followerHeartbeatTicker.C
	b.l.RUnlock()

	followerGauge := func(peerID string, suffix string, value float32) {
		labels := []metrics.Label{
			{
				Name:  "peer_id",
				Value: peerID,
			},
		}
		metrics.SetGaugeWithLabels([]string{"raft_storage", "follower", suffix}, value, labels)
	}
	for range tickerCh {
		b.l.RLock()
		if b.raft == nil {
			// We could be racing with teardown, which will stop the ticker
			// but that doesn't guarantee that we won't reach this line with a nil
			// b.raft.
			b.l.RUnlock()
			return
		}
		b.followerStates.l.RLock()
		myAppliedIndex := b.raft.AppliedIndex()
		for peerID, state := range b.followerStates.followers {
			timeSinceLastHeartbeat := time.Now().Sub(state.LastHeartbeat) / time.Millisecond
			followerGauge(peerID, "last_heartbeat_ms", float32(timeSinceLastHeartbeat))
			followerGauge(peerID, "applied_index_delta", float32(myAppliedIndex-state.AppliedIndex))

			if b.autopilotConfig.CleanupDeadServers && b.autopilotConfig.DeadServerLastContactThreshold != 0 {
				if state.LastHeartbeat.IsZero() || state.IsDead.Load() {
					continue
				}
				now := time.Now()
				if now.After(state.LastHeartbeat.Add(b.autopilotConfig.DeadServerLastContactThreshold)) {
					state.IsDead.Store(true)
				}
			}
		}
		b.followerStates.l.RUnlock()
		b.l.RUnlock()
	}
}

// StopAutopilot stops a running autopilot instance. This should only be called
// on the active node.
func (b *RaftBackend) StopAutopilot() {
	b.l.Lock()
	defer b.l.Unlock()

	if b.autopilot == nil {
		return
	}
	b.autopilot.Stop()
	b.autopilot = nil
	b.followerHeartbeatTicker.Stop()
}

// AutopilotState represents the health information retrieved from autopilot.
type AutopilotState struct {
	Healthy                    bool                        `json:"healthy" mapstructure:"healthy"`
	FailureTolerance           int                         `json:"failure_tolerance" mapstructure:"failure_tolerance"`
	Servers                    map[string]*AutopilotServer `json:"servers" mapstructure:"servers"`
	Leader                     string                      `json:"leader" mapstructure:"leader"`
	Voters                     []string                    `json:"voters" mapstructure:"voters"`
	NonVoters                  []string                    `json:"non_voters,omitempty" mapstructure:"non_voters,omitempty"`
	Upgrade                    *AutopilotUpgrade           `json:"upgrade_info,omitempty" mapstructure:"upgrade_info,omitempty"`
	OptimisticFailureTolerance int                         `json:"optimistic_failure_tolerance,omitempty" mapstructure:"optimistic_failure_tolerance,omitempty"`
}

// AutopilotServer represents the health information of individual server node
// retrieved from autopilot.
type AutopilotServer struct {
	ID             string            `json:"id" mapstructure:"id"`
	Name           string            `json:"name" mapstructure:"name"`
	Address        string            `json:"address" mapstructure:"address"`
	NodeStatus     string            `json:"node_status" mapstructure:"node_status"`
	LastContact    *ReadableDuration `json:"last_contact" mapstructure:"last_contact"`
	LastTerm       uint64            `json:"last_term" mapstructure:"last_term"`
	LastIndex      uint64            `json:"last_index" mapstructure:"last_index"`
	Healthy        bool              `json:"healthy" mapstructure:"healthy"`
	StableSince    time.Time         `json:"stable_since" mapstructure:"stable_since"`
	Status         string            `json:"status" mapstructure:"status"`
	Version        string            `json:"version" mapstructure:"version"`
	UpgradeVersion string            `json:"upgrade_version,omitempty" mapstructure:"upgrade_version,omitempty"`
	ReadReplica    bool              `json:"read_replica,omitempty" mapstructure:"read_replica,omitempty"`
	NodeType       string            `json:"node_type,omitempty" mapstructure:"node_type,omitempty"`
}

type AutopilotZone struct {
	Servers          []string `json:"servers,omitempty" mapstructure:"servers,omitempty"`
	Voters           []string `json:"voters,omitempty" mapstructure:"voters,omitempty"`
	FailureTolerance int      `json:"failure_tolerance,omitempty" mapstructure:"failure_tolerance,omitempty"`
}

type AutopilotUpgrade struct {
	Status                    string   `json:"status" mapstructure:"status"`
	TargetVersion             string   `json:"target_version,omitempty" mapstructure:"target_version,omitempty"`
	TargetVersionVoters       []string `json:"target_version_voters,omitempty" mapstructure:"target_version_voters,omitempty"`
	TargetVersionNonVoters    []string `json:"target_version_non_voters,omitempty" mapstructure:"target_version_non_voters,omitempty"`
	TargetVersionReadReplicas []string `json:"target_version_read_replicas,omitempty" mapstructure:"target_version_read_replicas,omitempty"`
	OtherVersionVoters        []string `json:"other_version_voters,omitempty" mapstructure:"other_version_voters,omitempty"`
	OtherVersionNonVoters     []string `json:"other_version_non_voters,omitempty" mapstructure:"other_version_non_voters,omitempty"`
	OtherVersionReadReplicas  []string `json:"other_version_read_replicas,omitempty" mapstructure:"other_version_read_replicas,omitempty"`
}

type AutopilotZoneUpgradeVersions struct {
	TargetVersionVoters    []string `json:"target_version_voters,omitempty" mapstructure:"target_version_voters,omitempty"`
	TargetVersionNonVoters []string `json:"target_version_non_voters,omitempty" mapstructure:"target_version_non_voters,omitempty"`
	OtherVersionVoters     []string `json:"other_version_voters,omitempty" mapstructure:"other_version_voters,omitempty"`
	OtherVersionNonVoters  []string `json:"other_version_non_voters,omitempty" mapstructure:"other_version_non_voters,omitempty"`
}

// ReadableDuration is a duration type that is serialized to JSON in human readable format.
type ReadableDuration time.Duration

func NewReadableDuration(dur time.Duration) *ReadableDuration {
	d := ReadableDuration(dur)
	return &d
}

func (d *ReadableDuration) String() string {
	return d.Duration().String()
}

func (d *ReadableDuration) Duration() time.Duration {
	if d == nil {
		return time.Duration(0)
	}
	return time.Duration(*d)
}

func (d *ReadableDuration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, d.Duration().String())), nil
}

func (d *ReadableDuration) UnmarshalJSON(raw []byte) (err error) {
	if d == nil {
		return fmt.Errorf("cannot unmarshal to nil pointer")
	}

	var dur time.Duration
	str := string(raw)
	if len(str) >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
		// quoted string
		dur, err = parseutil.ParseDurationSecond(str[1 : len(str)-1])
		if err != nil {
			return err
		}
	} else {
		// no quotes, not a string
		v, err := strconv.ParseFloat(str, 64)
		if err != nil {
			return err
		}
		dur = time.Duration(v)
	}

	*d = ReadableDuration(dur)
	return nil
}

func stringIDs(ids []raft.ServerID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

func autopilotToAPIState(state *autopilot.State) (*AutopilotState, error) {
	out := &AutopilotState{
		Healthy:          state.Healthy,
		FailureTolerance: state.FailureTolerance,
		Leader:           string(state.Leader),
		Voters:           stringIDs(state.Voters),
		NonVoters:        []string{},
		Servers:          make(map[string]*AutopilotServer),
	}

	for id, srv := range state.Servers {
		aps, err := autopilotToAPIServer(srv)
		if err != nil {
			return nil, err
		}
		out.Servers[string(id)] = aps

		if aps.NodeType == "non-voter" {
			out.NonVoters = append(out.NonVoters, string(id))
		}
	}

	return out, nil
}

func autopilotToAPIServer(srv *autopilot.ServerState) (*AutopilotServer, error) {
	apiSrv := &AutopilotServer{
		ID:          string(srv.Server.ID),
		Name:        srv.Server.Name,
		Address:     string(srv.Server.Address),
		NodeStatus:  string(srv.Server.NodeStatus),
		LastContact: NewReadableDuration(srv.Stats.LastContact),
		LastTerm:    srv.Stats.LastTerm,
		LastIndex:   srv.Stats.LastIndex,
		Healthy:     srv.Health.Healthy,
		StableSince: srv.Health.StableSince,
		Status:      string(srv.State),
		Version:     srv.Server.Version,
		NodeType:    string(srv.Server.NodeType),
	}

	return apiSrv, nil
}

// GetAutopilotServerState retrieves raft cluster state from autopilot to
// return over the API.
func (b *RaftBackend) GetAutopilotServerState(ctx context.Context) (*AutopilotState, error) {
	b.l.RLock()
	defer b.l.RUnlock()

	if b.raft == nil {
		return nil, errors.New("raft storage is not initialized")
	}

	if b.autopilot == nil {
		return nil, nil
	}

	apState := b.autopilot.GetState()
	if apState == nil {
		return nil, nil
	}

	return autopilotToAPIState(apState)
}

func (b *RaftBackend) DisableAutopilot() {
	b.l.Lock()
	b.disableAutopilot = true
	b.l.Unlock()
}

// SetupAutopilot gathers information required to configure autopilot and starts
// it. If autopilot is disabled, this function does nothing.
func (b *RaftBackend) SetupAutopilot(ctx context.Context, storageConfig *AutopilotConfig, followerStates *FollowerStates, disable bool) {
	b.l.Lock()
	if disable || api.ReadBaoVariable("BAO_RAFT_AUTOPILOT_DISABLE") != "" {
		b.disableAutopilot = true
	}

	if b.disableAutopilot {
		b.logger.Info("disabling autopilot")
		b.l.Unlock()
		return
	}

	// Start with a default config
	b.autopilotConfig = b.defaultAutopilotConfig()

	// Merge the setting provided over the API
	b.autopilotConfig.Merge(storageConfig)

	// Create the autopilot delegate
	b.delegate = NewDelegate(b)

	// Create the autopilot instance
	options := []autopilot.Option{
		autopilot.WithLogger(b.logger),
		autopilot.WithPromoter(&CustomPromoter{}),
	}
	if b.autopilotReconcileInterval != 0 {
		options = append(options, autopilot.WithReconcileInterval(b.autopilotReconcileInterval))
	}
	if b.autopilotUpdateInterval != 0 {
		options = append(options, autopilot.WithUpdateInterval(b.autopilotUpdateInterval))
	}
	b.autopilot = autopilot.New(b.raft, b.delegate, options...)
	b.followerStates = followerStates
	b.followerHeartbeatTicker = time.NewTicker(1 * time.Second)

	b.l.Unlock()

	b.logger.Info("starting autopilot", "config", b.autopilotConfig, "reconcile_interval", b.autopilotReconcileInterval)
	b.autopilot.Start(ctx)

	go b.startFollowerHeartbeatTracker()
}
