package capture

import (
	"fmt"
	"io"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type PacketWriter interface {
	WritePacket(ci gopacket.CaptureInfo, data []byte) error
	Flush() error
}

type PcapWriter struct {
	pcapWriter    *pcapgo.Writer
	headerWritten bool
	linkType      layers.LinkType
	snaplen       uint32
}

func NewPcapWriter(w io.Writer, linkType layers.LinkType, snaplen uint32) *PcapWriter {
	return &PcapWriter{
		pcapWriter: pcapgo.NewWriter(w),
		linkType:   linkType,
		snaplen:    snaplen,
	}
}

func (w *PcapWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	if !w.headerWritten {
		if err := w.pcapWriter.WriteFileHeader(w.snaplen, w.linkType); err != nil {
			return fmt.Errorf("error writing file header: %w", err)
		}
	}
	return w.pcapWriter.WritePacket(ci, data)
}

func (w *PcapWriter) Flush() error {
	return nil
}
