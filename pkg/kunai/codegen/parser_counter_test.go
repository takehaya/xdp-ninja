package codegen

import (
	"errors"
	"testing"

	"testing/fstest"

	"github.com/cilium/ebpf/asm"

	"github.com/takehaya/xdp-ninja/pkg/kunai/parser"
	"github.com/takehaya/xdp-ninja/pkg/kunai/resolve"
	"github.com/takehaya/xdp-ninja/pkg/kunai/vocab"
)

// TestParserCounterSlotAllocation pins the slot offsets the codegen
// hands out for ParserCounter instances. The lower-bound check
// surfaces the "no third counter without a region rethink" footgun
// added by parser_counter.go's gap-region carve-out.
func TestParserCounterSlotAllocation(t *testing.T) {
	for i, want := range []int16{-152, -160} {
		got, err := parserCounterSlot(i)
		if err != nil {
			t.Fatalf("parserCounterSlot(%d): %v", i, err)
		}
		if got != want {
			t.Errorf("parserCounterSlot(%d) = %d, want %d", i, got, want)
		}
	}
	if _, err := parserCounterSlot(parserCounterMaxSlots); err == nil {
		t.Errorf("expected error for slot index %d (>= max %d)", parserCounterMaxSlots, parserCounterMaxSlots)
	}
}

// TestGenIPv4ParserCounterMachine compiles a synthetic vocab whose
// IPv4 parser uses ParserCounter to walk the option trailer. The
// test confirms Gen accepts the counter-driven ParseStateMachine
// and emits the four observable shapes:
//
//  1. Counter slot zero-init at machine entry.
//  2. Counter set (StoreMem to the slot after the byte-expression
//     load).
//  3. Counter dispatch in the bpf_loop callback (JEq slot, 0).
//  4. Counter decrement in the sibling body (Load → Sub → Store).
//
// Asserts only the structural presence of each — instruction-by-
// instruction matching belongs in dsltest, where the verifier and
// runtime confirm the stream is correct.
func TestGenIPv4ParserCounterMachine(t *testing.T) {
	const ipv4Source = `
header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_length;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> checksum;
    bit<32> src;
    bit<32> dst;
}

const bit<16> IPV4_ETH_ETHERTYPE = 0x0800;

extern ParserCounter {
    ParserCounter();
    void set(in bit<8> value);
    void decrement(in bit<8> value);
    bool is_zero();
}

parser IPv4Parser(packet_in pkt, out ipv4_h hdr) {
    ParserCounter() pc;
    state start {
        pkt.extract(hdr);
        pc.set(((bit<8>)(hdr.ihl - 5)) << 5);
        transition select(hdr.version, hdr.ihl) {
            (4, 5):  accept;
            (4, _):  walk;
            default: reject;
        }
    }
    state walk {
        transition select(pc.is_zero()) {
            true:  accept;
            false: consume;
        }
    }
    state consume {
        pkt.advance(8);
        pc.decrement(1);
        transition walk;
    }
}
`
	const ethSource = `
header eth_h {
    bit<48> dst;
    bit<48> src;
    bit<16> ethertype;
}
parser ETH(packet_in pkt, out eth_h hdr) {
    state start { pkt.extract(hdr); transition accept; }
}
`
	fsys := fstest.MapFS{
		"vocab/eth.p4":  &fstest.MapFile{Data: []byte(ethSource)},
		"vocab/ipv4.p4": &fstest.MapFile{Data: []byte(ipv4Source)},
	}
	specs, err := vocab.Load(fsys, "vocab")
	if err != nil {
		t.Fatalf("vocab.Load: %v", err)
	}

	f, err := parser.Parse("eth/ipv4", "", nil)
	if err != nil {
		t.Fatalf("parser.Parse: %v", err)
	}
	prog, err := resolve.Resolve(f, specs, nil)
	if err != nil {
		t.Fatalf("resolve.Resolve: %v", err)
	}

	out, err := Gen(prog, Capabilities{})
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if len(out.Main) == 0 {
		t.Fatal("expected non-empty Main stream")
	}

	slot0, err := parserCounterSlot(0)
	if err != nil {
		t.Fatalf("parserCounterSlot(0): %v", err)
	}
	stream := append(asm.Instructions{}, out.Main...)
	stream = append(stream, out.Callbacks...)

	if err := assertCounterStoreToR10(stream, slot0); err != nil {
		t.Errorf("counter slot init: %v", err)
	}
	// JEq.Imm 0 against the counter slot register sits in the
	// bpf_loop callback. Sample the union for the opcode shape.
	if !containsOp(stream, asm.JEq.Imm(asm.R0, 0, "").OpCode) {
		t.Errorf("expected JEq.Imm matching counter-is-zero branch")
	}
	// The decrement signature is Load slot → Sub.Imm 1 → Store slot.
	// Asserting the triple pins the emit shape against drift more
	// tightly than a bare "any Sub.Imm 1" match.
	if !hasCounterDecrement(stream, 1) {
		t.Errorf("expected Load(slot) + Sub.Imm 1 + Store(slot) decrement triple")
	}
}

// assertCounterStoreToR10 checks that some StoreMem references the
// given R10-relative slot, which doubles as proof that the slot
// init prelude (`Mov.Imm Rx, 0; StoreMem R10[slot], Rx`) ran.
func assertCounterStoreToR10(stream asm.Instructions, slot int16) error {
	for _, ins := range stream {
		if ins.Dst == asm.R10 && int16(ins.Offset) == slot && ins.OpCode.Class().IsStore() {
			return nil
		}
	}
	return errors.New("no StoreMem to expected counter slot")
}

func containsOp(stream asm.Instructions, op asm.OpCode) bool {
	for _, ins := range stream {
		if ins.OpCode == op {
			return true
		}
	}
	return false
}

// hasCounterDecrement looks for the Load(slot) → Sub.Imm imm →
// Store(slot) triple anywhere in the stream. The slot offset must
// match across the load/store, which fingerprints the pattern as
// "decrement of a stack slot by imm" without taking on responsibility
// for which counter the slot belongs to.
func hasCounterDecrement(stream asm.Instructions, imm int32) bool {
	for i := 0; i+2 < len(stream); i++ {
		ld, sub, st := stream[i], stream[i+1], stream[i+2]
		if !ld.OpCode.Class().IsLoad() || !st.OpCode.Class().IsStore() {
			continue
		}
		if ld.Offset != st.Offset {
			continue
		}
		if sub.OpCode != asm.Sub.Imm(asm.R0, imm).OpCode {
			continue
		}
		if sub.Constant != int64(imm) {
			continue
		}
		return true
	}
	return false
}

