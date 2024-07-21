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

type PcapNgWriter struct {
	ngWriter *pcapgo.NgWriter
	linkType layers.LinkType
	snaplen  uint32
	os       string
	hostname string
}

func NewPcapNgWriter(w io.Writer, linkType layers.LinkType, snaplen uint32, ifaceName string, ifaceIndex int, hardware, os, hostname string) (*PcapNgWriter, error) {
	intf := pcapgo.NgInterface{
		Name:        ifaceName,
		Index:       ifaceIndex,
		LinkType:    linkType,
		SnapLength:  snaplen,
		OS:          os,
		Description: fmt.Sprintf("hostname: %q", hostname),
	}
	ngOpts := pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Hardware:    hardware,
			OS:          os,
			Application: "capper",
		},
	}
	ngWriter, err := pcapgo.NewNgWriterInterface(w, intf, ngOpts)
	if err != nil {
		return nil, err
	}
	return &PcapNgWriter{
		ngWriter: ngWriter,
		linkType: linkType,
		snaplen:  snaplen,
		os:       os,
		hostname: hostname,
	}, nil
}

func (w *PcapNgWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	return w.ngWriter.WritePacket(ci, data)
}

func (w *PcapNgWriter) Flush() error {
	return w.ngWriter.Flush()
}

func (w *PcapNgWriter) AddInterface(name string, index int, linkType layers.LinkType) (int, error) {
	return w.ngWriter.AddInterface(pcapgo.NgInterface{
		Name:        name,
		Index:       index,
		LinkType:    linkType,
		SnapLength:  w.snaplen,
		OS:          w.os,
		Description: fmt.Sprintf("hostname: %q", w.hostname),
	})
}
