package capture

import (
	"encoding/binary"
	"testing"
)

func TestParsePacket(t *testing.T) {
	// metadata (8B): action=2 (PASS), mode=1 (exit), pad=0
	// + packet data
	pktData := []byte{0xde, 0xad, 0xbe, 0xef}

	raw := make([]byte, MetadataSize+len(pktData))
	binary.NativeEndian.PutUint32(raw[0:4], 2) // action = XDP_PASS
	raw[4] = 1                                  // mode = exit
	raw[5] = 0                                  // pad
	raw[6] = 0
	raw[7] = 0
	copy(raw[MetadataSize:], pktData)

	pkt, err := ParseRawSample(raw)
	if err != nil {
		t.Fatalf("ParseRawSample failed: %v", err)
	}

	if pkt.Action != 2 {
		t.Errorf("Action = %d, want 2", pkt.Action)
	}
	if pkt.Mode != 1 {
		t.Errorf("Mode = %d, want 1", pkt.Mode)
	}
	if len(pkt.Data) != len(pktData) {
		t.Errorf("Data length = %d, want %d", len(pkt.Data), len(pktData))
	}
	if pkt.Data[0] != 0xde || pkt.Data[3] != 0xef {
		t.Errorf("Data = %x, want deadbeef", pkt.Data)
	}
}

func TestParsePacketTooShort(t *testing.T) {
	raw := make([]byte, 3) // less than MetadataSize (8)
	_, err := ParseRawSample(raw)
	if err == nil {
		t.Fatal("expected error for short sample, got nil")
	}
}

func TestParsePacketMetadataOnly(t *testing.T) {
	// metadata only, no packet data (edge case)
	raw := make([]byte, MetadataSize)
	binary.NativeEndian.PutUint32(raw[0:4], 0) // action = 0
	raw[4] = 0                                  // mode = entry

	pkt, err := ParseRawSample(raw)
	if err != nil {
		t.Fatalf("ParseRawSample failed: %v", err)
	}
	if len(pkt.Data) != 0 {
		t.Errorf("Data length = %d, want 0", len(pkt.Data))
	}
}
