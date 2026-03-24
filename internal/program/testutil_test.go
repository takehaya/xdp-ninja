package program

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

const xdpFuncName = "xdp_pass_test"

const xdpPassSource = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("xdp")
int xdp_pass_test(struct xdp_md *ctx) { return 2; }
char _license[] SEC("license") = "GPL";
`

func skipIfNotRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
}

// compileXDPObj compiles the dummy XDP program with BTF.
// Skips the test if clang is not available.
func compileXDPObj(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "xdp.c")
	objFile := filepath.Join(dir, "xdp.o")
	os.WriteFile(srcFile, []byte(xdpPassSource), 0644)

	out, err := exec.Command("clang", "-O2", "-g", "-target", "bpf", "-c", srcFile, "-o", objFile).CombinedOutput()
	if err != nil {
		t.Skipf("clang not available: %v\n%s", err, out)
	}
	return objFile
}

// loadDummyXDP compiles and loads a minimal XDP_PASS program with BTF.
func loadDummyXDP(t *testing.T) *ebpf.Program {
	t.Helper()
	skipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(compileXDPObj(t))
	if err != nil {
		t.Fatalf("loading collection spec: %v", err)
	}

	var objs struct {
		Prog *ebpf.Program `ebpf:"xdp_pass_test"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("loading XDP program: %v", err)
	}
	t.Cleanup(func() { objs.Prog.Close() })
	return objs.Prog
}

// loadProbeOrFail loads a probe and fails with verifier output on error.
func loadProbeOrFail(t *testing.T, xdpProg *ebpf.Program, filterExpr string, exit bool) *Probe {
	t.Helper()
	var probe *Probe
	var err error
	if exit {
		probe, err = LoadExit(xdpProg, xdpFuncName, filterExpr)
	} else {
		probe, err = LoadEntry(xdpProg, xdpFuncName, filterExpr)
	}
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error:\n%+v", ve)
		}
		t.Fatalf("loading probe: %v", err)
	}
	t.Cleanup(func() { probe.Close() })
	return probe
}
