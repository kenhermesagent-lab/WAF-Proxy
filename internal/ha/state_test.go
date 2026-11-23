package ha

import "testing"

func TestNextLegalTransitions(t *testing.T) {
	cases := []struct {
		from  State
		event Event
		want  State
	}{
		{StateStandby, EventReady, StateReadyStandby},
		{StateReadyStandby, EventPromote, StatePromoting},
		{StatePromoting, EventReady, StateActive},
		{StateActive, EventDrain, StateDraining},
		{StateDraining, EventDemote, StateDemoting},
		{StateDemoting, EventReady, StateStandby},
		{StateActive, EventFence, StateFenced},
		{StateFenced, EventRecover, StateStandby},
		{StateActive, EventBreak, StateSplitBrainRisk},
		{StateSplitBrainRisk, EventRecover, StateStandby},
		{StateReadyStandby, EventBreak, StateStandby},
	}
	for _, tc := range cases {
		got, _, err := Next(tc.from, tc.event)
		if err != nil {
			t.Fatalf("%s + %s: %v", tc.from, tc.event, err)
		}
		if got != tc.want {
			t.Fatalf("%s + %s = %s, want %s", tc.from, tc.event, got, tc.want)
		}
	}
}

func TestNextRefusesIllegalTransitions(t *testing.T) {
	cases := []struct {
		from  State
		event Event
	}{
		{StateStandalone, EventPromote},
		{StateStandby, EventPromote},
		{StateActive, EventPromote},
		{StateActive, EventReady},
		{StateDraining, EventPromote},
		{StateFenced, EventPromote},
	}
	for _, tc := range cases {
		got, actions, err := Next(tc.from, tc.event)
		if err == nil {
			t.Fatalf("%s + %s was allowed", tc.from, tc.event)
		}
		if got != tc.from || len(actions) != 0 {
			t.Fatalf("%s + %s changed state to %s with actions %v", tc.from, tc.event, got, actions)
		}
	}
}

func TestServingStates(t *testing.T) {
	for _, s := range []State{StateActive, StateStandalone} {
		if !Serving(s) {
			t.Errorf("%s should serve", s)
		}
	}
	for _, s := range []State{StateStandby, StateReadyStandby, StateDraining, StatePromoting, StateDemoting, StateFenced, StateSplitBrainRisk, StateParked} {
		if Serving(s) {
			t.Errorf("%s must not serve", s)
		}
	}
}
