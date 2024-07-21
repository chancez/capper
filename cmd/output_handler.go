package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type commonOutputHandler struct {
	handler capture.PacketHandler
}

func newCommonOutputHandler(linkType layers.LinkType, snaplen uint32, printPackets bool, outputPath string, isDir bool) *commonOutputHandler {
	var handlers []capture.PacketHandler
	if printPackets {
		handlers = append(handlers, capture.PacketPrinterHandler)
	}
	if outputPath != "" {
		outputFileHandler := newOutputFileHandler(outputPath, isDir, linkType, snaplen)
		handlers = append(handlers, outputFileHandler)
	}
	handler := capture.ChainPacketHandlers(handlers...)
	return &commonOutputHandler{
		handler: handler,
	}
}

func (ch *commonOutputHandler) HandlePacket(p gopacket.Packet) error {
	return ch.handler.HandlePacket(p)
}

func (ch *commonOutputHandler) Flush() error {
	return ch.handler.Flush()
}

type outputFileHandler struct {
	outputPath string
	isDir      bool

	writers  map[string]capture.PacketWriter
	closers  []io.Closer
	linkType layers.LinkType
	snaplen  uint32
}

func newOutputFileHandler(outputPath string, isDir bool, linkType layers.LinkType, snaplen uint32) *outputFileHandler {
	return &outputFileHandler{
		outputPath: outputPath,
		isDir:      isDir,
		writers:    make(map[string]capture.PacketWriter),
		linkType:   linkType,
		snaplen:    snaplen,
	}
}

func (h *outputFileHandler) HandlePacket(p gopacket.Packet) error {
	ad, err := getCapperAncillaryData(p)
	if err != nil {
		return fmt.Errorf("error getting packet ancillary data: %w", err)
	}
	identifier := normalizeFilename(ad.NodeName, ad.Netns, ad.IfaceName, capperpb.PcapOutputFormat_OUTPUT_FORMAT_PCAP)
	packetWriter, exists := h.writers[identifier]
	if !exists {
		var w io.Writer
		if h.isDir {
			f, err := os.Create(filepath.Join(h.outputPath, identifier))
			if err != nil {
				return fmt.Errorf("error opening output: %w", err)
			}
			h.closers = append(h.closers, f)
			w = f
		} else if h.outputPath == "-" {
			w = os.Stdout
		} else {
			f, err := os.Create(h.outputPath)
			if err != nil {
				return fmt.Errorf("error opening output: %w", err)
			}
			h.closers = append(h.closers, f)
			w = f
		}
		packetWriter = capture.NewPcapWriter(w, h.linkType, h.snaplen)
	}
	return packetWriter.WritePacket(p.Metadata().CaptureInfo, p.Data())
}

func (h *outputFileHandler) Flush() error {
	var err error
	for _, w := range h.writers {
		err = errors.Join(err, w.Flush())
	}
	for _, closer := range h.closers {
		err = errors.Join(err, closer.Close())
	}
	return err
}

func getCapperAncillaryData(p gopacket.Packet) (*capperpb.AncillaryPacketData, error) {
	pancillaryData := p.Metadata().AncillaryData
	if len(pancillaryData) == 0 {
		return nil, fmt.Errorf("no gopacket AncillaryData")
	}
	var ancillaryData *capperpb.AncillaryPacketData
	for _, ad := range pancillaryData {
		var ok bool
		ancillaryData, ok = ad.(*capperpb.AncillaryPacketData)
		if ok {
			break
		}
	}
	if ancillaryData == nil {
		return nil, fmt.Errorf("no capper AncillaryPacketData found in gopacket AncillaryData")
	}
	return ancillaryData, nil
}
