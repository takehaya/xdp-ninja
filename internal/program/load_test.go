package program

import (
	"testing"
)

// TestBpfEntryLoad verifies that the fentry program passes the verifier.
func TestBpfEntryLoad(t *testing.T) {
	probe := loadProbeOrFail(t, loadDummyXDP(t), "", false)
	if probe.EventsMap == nil {
		t.Error("EventsMap is nil")
	}
}

// TestBpfExitLoad verifies that the fexit program passes the verifier.
func TestBpfExitLoad(t *testing.T) {
	probe := loadProbeOrFail(t, loadDummyXDP(t), "", true)
	if probe.EventsMap == nil {
		t.Error("EventsMap is nil")
	}
}

// TestBpfEntryWithFilter verifies fentry + cbpfc filter passes the verifier.
func TestBpfEntryWithFilter(t *testing.T) {
	xdpProg := loadDummyXDP(t)
	for _, expr := range []string{"arp", "icmp", "tcp port 80", "host 10.0.0.1"} {
		t.Run(expr, func(t *testing.T) {
			loadProbeOrFail(t, xdpProg, expr, false)
		})
	}
}

// TestBpfExitWithFilter verifies fexit + cbpfc filter passes the verifier.
func TestBpfExitWithFilter(t *testing.T) {
	xdpProg := loadDummyXDP(t)
	for _, expr := range []string{"arp", "icmp", "tcp port 80", "host 10.0.0.1"} {
		t.Run(expr, func(t *testing.T) {
			loadProbeOrFail(t, xdpProg, expr, true)
		})
	}
}
