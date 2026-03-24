package attach

import (
	"testing"
)

func TestFindXDPProgramNoInterface(t *testing.T) {
	_, err := FindXDPProgram("nonexistent_iface_xyz")
	if err == nil {
		t.Fatal("expected error for nonexistent interface, got nil")
	}
}
