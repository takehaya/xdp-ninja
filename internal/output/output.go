// Package output writes captured packets in pcap format to a file or stdout.
package output

import (
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/takehaya/xdp-ninja/internal/capture"
)

// Writer writes captured packets in pcapng format.
type Writer struct {
	pcapWriter *pcapgo.NgWriter
	file       *os.File // non-nil only when writing to a file (not stdout)
}

// NewWriter creates a pcapng writer. If path is empty, writes to stdout.
func NewWriter(path string) (*Writer, error) {
	var dest io.Writer
	w := &Writer{}

	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("creating pcap file: %w", err)
		}
		w.file = f
		dest = f
	} else {
		dest = os.Stdout
	}

	pw, err := pcapgo.NewNgWriter(dest, layers.LinkTypeEthernet)
	if err != nil {
		if w.file != nil {
			w.file.Close()
		}
		return nil, fmt.Errorf("creating pcap writer: %w", err)
	}
	w.pcapWriter = pw

	return w, nil
}

// Write outputs a captured packet.
func (w *Writer) Write(pkt capture.Packet) error {
	ci := gopacket.CaptureInfo{
		Timestamp:     pkt.Timestamp,
		CaptureLength: len(pkt.Data),
		Length:        len(pkt.Data),
	}
	if err := w.pcapWriter.WritePacket(ci, pkt.Data); err != nil {
		return fmt.Errorf("writing pcap packet: %w", err)
	}
	return w.pcapWriter.Flush()
}

// Close flushes and closes resources.
func (w *Writer) Close() error {
	if err := w.pcapWriter.Flush(); err != nil {
		return err
	}
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}
