package program

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdp-ninja/internal/attach"
	"github.com/takehaya/xdp-ninja/internal/filter"
	"github.com/takehaya/xdp-ninja/internal/testutil"
)

// argFilterTestSource defines a noinline function with an extra u32 parameter.
// The parameter value is derived from packet data so we can control it via ping.
const argFilterTestSource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Test function called with filter_id=42. Filters matching 42 receive events.

__attribute__((noinline))
int process_with_id(struct xdp_md *ctx, __u32 filter_id) {
    volatile __u32 id = filter_id; // prevent optimization
    return (id > 0) ? 2 : 1;
}

SEC("xdp")
int xdp_argfilter_test(struct xdp_md *ctx) {
    // Always pass 42 as the filter_id
    return process_with_id(ctx, 42);
}

char _license[] SEC("license") = "GPL";
`

func loadArgFilterTestCollection(t *testing.T) *ebpf.Program {
	t.Helper()
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, argFilterTestSource))
	if err != nil {
		t.Fatalf("spec: %v", err)
	}

	var objs struct {
		XDP *ebpf.Program `ebpf:"xdp_argfilter_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = objs.XDP.Close() })

	return objs.XDP
}

// setupVethForArgFilter creates a veth pair and attaches the given XDP program.
func setupVethForArgFilter(t *testing.T, xdpProg *ebpf.Program) string {
	t.Helper()
	return setupVeth(t, xdpProg, "argtest0", "argtest1", "10.88.0.1", "10.88.0.2")
}

// countArgFilterEvents attaches fentry with arg filters, sends packets, and counts events.
func countArgFilterEvents(t *testing.T, targetProg *ebpf.Program, funcName, iface string, argFilters []filter.ArgFilter) int {
	t.Helper()
	return countEvents(t, targetProg, funcName, iface, "10.88.0.2", false, argFilters, 3, 3)
}

// TestArgFilter verifies that argument filtering works correctly.
// The noinline function process_with_id is always called with filter_id=42.
func TestArgFilter(t *testing.T) {
	xdpProg := loadArgFilterTestCollection(t)
	iface := setupVethForArgFilter(t, xdpProg)

	// First verify we can get the function parameters
	params, err := attach.GetFuncParams(xdpProg, "process_with_id")
	if err != nil {
		t.Fatalf("GetFuncParams: %v", err)
	}
	t.Logf("Found %d filterable parameters", len(params))
	for _, p := range params {
		t.Logf("  %s: index=%d, size=%d, signed=%v", p.Name, p.Index, p.Size, p.Signed)
	}

	if len(params) == 0 {
		t.Skip("No filterable parameters found (BTF may not include parameter names)")
	}

	// Find the filter_id parameter
	var filterIDParam *attach.FuncParamInfo
	for i := range params {
		if params[i].Name == "filter_id" {
			filterIDParam = &params[i]
			break
		}
	}
	if filterIDParam == nil {
		t.Skip("filter_id parameter not found in BTF")
	}

	t.Run("no_filter", func(t *testing.T) {
		count := countArgFilterEvents(t, xdpProg, "process_with_id", iface, nil)
		if count == 0 {
			t.Fatal("expected events without filter, got 0")
		}
		t.Logf("received %d events (no filter)", count)
	})

	t.Run("exact_match_hit", func(t *testing.T) {
		// filter_id=42 should match
		filters := []filter.ArgFilter{{
			ParamName:  "filter_id",
			ParamIndex: filterIDParam.Index,
			ParamSize:  filterIDParam.Size,
			Signed:     filterIDParam.Signed,
			Op:         filter.OpEqual,
			Value:      42,
		}}
		count := countArgFilterEvents(t, xdpProg, "process_with_id", iface, filters)
		if count == 0 {
			t.Fatal("expected events with matching filter (filter_id=42), got 0")
		}
		t.Logf("received %d events (filter_id=42)", count)
	})

	t.Run("exact_match_miss", func(t *testing.T) {
		// filter_id=99 should not match
		filters := []filter.ArgFilter{{
			ParamName:  "filter_id",
			ParamIndex: filterIDParam.Index,
			ParamSize:  filterIDParam.Size,
			Signed:     filterIDParam.Signed,
			Op:         filter.OpEqual,
			Value:      99,
		}}
		count := countArgFilterEvents(t, xdpProg, "process_with_id", iface, filters)
		if count != 0 {
			t.Fatalf("expected 0 events with non-matching filter (filter_id=99), got %d", count)
		}
		t.Logf("received %d events (filter_id=99, expected 0)", count)
	})

	t.Run("range_hit", func(t *testing.T) {
		// filter_id=40..50 should match (42 is in range)
		filters := []filter.ArgFilter{{
			ParamName:  "filter_id",
			ParamIndex: filterIDParam.Index,
			ParamSize:  filterIDParam.Size,
			Signed:     filterIDParam.Signed,
			Op:         filter.OpRange,
			Value:      40,
			MaxValue:   50,
		}}
		count := countArgFilterEvents(t, xdpProg, "process_with_id", iface, filters)
		if count == 0 {
			t.Fatal("expected events with range filter (filter_id=40..50), got 0")
		}
		t.Logf("received %d events (filter_id=40..50)", count)
	})

	t.Run("range_miss", func(t *testing.T) {
		// filter_id=100..200 should not match
		filters := []filter.ArgFilter{{
			ParamName:  "filter_id",
			ParamIndex: filterIDParam.Index,
			ParamSize:  filterIDParam.Size,
			Signed:     filterIDParam.Signed,
			Op:         filter.OpRange,
			Value:      100,
			MaxValue:   200,
		}}
		count := countArgFilterEvents(t, xdpProg, "process_with_id", iface, filters)
		if count != 0 {
			t.Fatalf("expected 0 events with non-matching range filter (filter_id=100..200), got %d", count)
		}
		t.Logf("received %d events (filter_id=100..200, expected 0)", count)
	})

	t.Run("greater_equal_hit", func(t *testing.T) {
		// filter_id>=40 should match
		filters := []filter.ArgFilter{{
			ParamName:  "filter_id",
			ParamIndex: filterIDParam.Index,
			ParamSize:  filterIDParam.Size,
			Signed:     filterIDParam.Signed,
			Op:         filter.OpGreaterEqual,
			Value:      40,
		}}
		count := countArgFilterEvents(t, xdpProg, "process_with_id", iface, filters)
		if count == 0 {
			t.Fatal("expected events with >= filter (filter_id>=40), got 0")
		}
		t.Logf("received %d events (filter_id>=40)", count)
	})

	t.Run("greater_equal_miss", func(t *testing.T) {
		// filter_id>=100 should not match
		filters := []filter.ArgFilter{{
			ParamName:  "filter_id",
			ParamIndex: filterIDParam.Index,
			ParamSize:  filterIDParam.Size,
			Signed:     filterIDParam.Signed,
			Op:         filter.OpGreaterEqual,
			Value:      100,
		}}
		count := countArgFilterEvents(t, xdpProg, "process_with_id", iface, filters)
		if count != 0 {
			t.Fatalf("expected 0 events with >= filter (filter_id>=100), got %d", count)
		}
		t.Logf("received %d events (filter_id>=100, expected 0)", count)
	})

	t.Run("less_equal_hit", func(t *testing.T) {
		// filter_id<=50 should match
		filters := []filter.ArgFilter{{
			ParamName:  "filter_id",
			ParamIndex: filterIDParam.Index,
			ParamSize:  filterIDParam.Size,
			Signed:     filterIDParam.Signed,
			Op:         filter.OpLessEqual,
			Value:      50,
		}}
		count := countArgFilterEvents(t, xdpProg, "process_with_id", iface, filters)
		if count == 0 {
			t.Fatal("expected events with <= filter (filter_id<=50), got 0")
		}
		t.Logf("received %d events (filter_id<=50)", count)
	})

	t.Run("less_equal_miss", func(t *testing.T) {
		// filter_id<=10 should not match
		filters := []filter.ArgFilter{{
			ParamName:  "filter_id",
			ParamIndex: filterIDParam.Index,
			ParamSize:  filterIDParam.Size,
			Signed:     filterIDParam.Signed,
			Op:         filter.OpLessEqual,
			Value:      10,
		}}
		count := countArgFilterEvents(t, xdpProg, "process_with_id", iface, filters)
		if count != 0 {
			t.Fatalf("expected 0 events with <= filter (filter_id<=10), got %d", count)
		}
		t.Logf("received %d events (filter_id<=10, expected 0)", count)
	})
}
