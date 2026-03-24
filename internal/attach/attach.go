// Package attach finds existing XDP programs on network interfaces.
package attach

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// XDPInfo holds information about the existing XDP program on an interface.
type XDPInfo struct {
	ProgID    uint32
	Program   *ebpf.Program
	FuncName  string
	IfaceName string
}

// FindXDPProgramByID gets an XDP program by its BPF program ID.
func FindXDPProgramByID(progID uint32) (*XDPInfo, error) {
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
	if err != nil {
		return nil, fmt.Errorf("getting program (id=%d): %w", progID, err)
	}

	info, err := prog.Info()
	if err != nil {
		prog.Close()
		return nil, fmt.Errorf("getting program info (id=%d): %w", progID, err)
	}

	return &XDPInfo{
		ProgID:   progID,
		Program:  prog,
		FuncName: info.Name,
	}, nil
}

// FindXDPProgram finds the existing XDP program on the given interface.
func FindXDPProgram(ifaceName string) (*XDPInfo, error) {
	nl, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	xdp := nl.Attrs().Xdp
	if xdp == nil || xdp.ProgId == 0 {
		return nil, fmt.Errorf("no XDP program attached to %s", ifaceName)
	}

	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(xdp.ProgId))
	if err != nil {
		return nil, fmt.Errorf("getting XDP program (id=%d): %w", xdp.ProgId, err)
	}

	info, err := prog.Info()
	if err != nil {
		prog.Close()
		return nil, fmt.Errorf("getting program info (id=%d): %w", xdp.ProgId, err)
	}

	return &XDPInfo{
		ProgID:    xdp.ProgId,
		Program:   prog,
		FuncName:  info.Name,
		IfaceName: ifaceName,
	}, nil
}
