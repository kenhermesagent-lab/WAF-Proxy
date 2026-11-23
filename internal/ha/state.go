package ha

import "fmt"

// State is this node's place in the pair. The names are the ones the console
// and `ha status` show, so an operator never has to translate.
type State string

const (
	StateStandalone     State = "standalone"
	StateStandby        State = "standby"
	StateReadyStandby   State = "ready-standby"
	StatePromoting      State = "promoting"
	StateActive         State = "active"
	StateDraining       State = "draining"
	StateDemoting       State = "demoting"
	StateFenced         State = "fenced"
	StateSplitBrainRisk State = "split-brain-risk"
	// StateParked is a standby whose automatic moves stopped after the pair
	// moved too often. Only an operator clears it, with a manual move.
	StateParked State = "parked"
)

// Event is something that happened, not something an operator wants. Keeping
// the two apart is what stops a refused promotion from being half-applied.
type Event string

const (
	EventStart   Event = "start"
	EventReady   Event = "ready"
	EventPromote Event = "promote"
	EventDemote  Event = "demote"
	EventDrain   Event = "drain"
	EventFence   Event = "fence"
	EventRecover Event = "recover"
	EventBreak   Event = "break"
)

// Action is work the caller must do after a transition. The state machine does
// not touch listeners or the database itself.
type Action string

const (
	ActionCloseListeners  Action = "close-listeners"
	ActionOpenListeners   Action = "open-listeners"
	ActionDrain           Action = "drain"
	ActionReloadEngines   Action = "reload-engines"
	ActionReconcileBans   Action = "reconcile-bans"
	ActionStopReplication Action = "stop-replication"
)

// Next applies one event. An illegal transition returns an error and the
// original state: a bug or a stale command must never promote a node by
// accident.
func Next(state State, event Event) (State, []Action, error) {
	switch state {
	case StateStandalone:
		// HA is off. Promotion is a configuration change, not an event.
		return state, nil, fmt.Errorf("ha: %s is the single-node state", state)
	case StateStandby:
		switch event {
		case EventStart:
			return StateStandby, nil, nil
		case EventReady:
			return StateReadyStandby, nil, nil
		case EventFence:
			return StateFenced, nil, nil
		}
	case StateReadyStandby:
		switch event {
		case EventPromote:
			return StatePromoting, []Action{ActionReloadEngines, ActionReconcileBans}, nil
		case EventBreak:
			return StateStandby, nil, nil
		case EventFence:
			return StateFenced, nil, nil
		}
	case StateActive:
		switch event {
		case EventDrain:
			return StateDraining, []Action{ActionDrain}, nil
		case EventDemote:
			return StateDemoting, []Action{ActionCloseListeners, ActionStopReplication}, nil
		case EventFence:
			return StateFenced, []Action{ActionCloseListeners, ActionStopReplication}, nil
		case EventBreak:
			return StateSplitBrainRisk, []Action{ActionCloseListeners}, nil
		}
	case StatePromoting:
		switch event {
		case EventReady:
			return StateActive, []Action{ActionOpenListeners}, nil
		case EventBreak:
			return StateStandby, []Action{ActionCloseListeners}, nil
		}
	case StateDraining:
		switch event {
		case EventDemote:
			return StateDemoting, []Action{ActionCloseListeners, ActionStopReplication}, nil
		case EventBreak:
			return StateStandby, nil, nil
		}
	case StateDemoting:
		if event == EventReady {
			return StateStandby, nil, nil
		}
	case StateFenced:
		if event == EventRecover {
			return StateStandby, nil, nil
		}
	case StateSplitBrainRisk:
		if event == EventRecover {
			return StateStandby, nil, nil
		}
	case StateParked:
		if event == EventRecover {
			return StateStandby, nil, nil
		}
	}
	return state, nil, fmt.Errorf("ha: cannot apply %q in state %q", event, state)
}

// Serving reports whether the data plane may answer requests.
func Serving(state State) bool { return state == StateActive || state == StateStandalone }
