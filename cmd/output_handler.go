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

func newCommonOutputHandler(linkType layers.LinkType, snaplen uint32, printPackets bool, outputPath string, isDir bool, outputFormat capperpb.PcapOutputFormat) *commonOutputHandler {
	var handlers []capture.PacketHandler
	if printPackets {
		handlers = append(handlers, capture.PacketPrinterHandler)
	}
	if outputPath != "" {
		outputFileHandler := newOutputFileHandler(outputPath, isDir, linkType, snaplen, outputFormat)
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

	writers map[string]capture.PacketWriter
	// map from nodeName -> network namespace -> interfaceName
	closers      []io.Closer
	linkType     layers.LinkType
	snaplen      uint32
	outputFormat capperpb.PcapOutputFormat

	// interfaceConfigured tracks if we've configured a given interface when
	// using an NgWriter. The map is keyed by the interface index.
	// Unfortunately, since pcapng didn't consider multi-host captures, this
	// means the same interface index across different hosts may clash.
	// TODO: Update NgWriter to key by more than the interface index.
	interfaceConfigured map[int]struct{}
}

func newOutputFileHandler(outputPath string, isDir bool, linkType layers.LinkType, snaplen uint32, outputFormat capperpb.PcapOutputFormat) *outputFileHandler {
	return &outputFileHandler{
		outputPath:          outputPath,
		isDir:               isDir,
		writers:             make(map[string]capture.PacketWriter),
		linkType:            linkType,
		snaplen:             snaplen,
		outputFormat:        outputFormat,
		interfaceConfigured: make(map[int]struct{}),
	}
}

func (h *outputFileHandler) HandlePacket(p gopacket.Packet) error {
	ad, err := getCapperAncillaryData(p)
	if err != nil {
		return fmt.Errorf("error getting packet ancillary data: %w", err)
	}

	var identifier string
	if h.isDir {
		identifier = normalizeFilename(ad.NodeName, ad.Netns, ad.IfaceName, h.outputFormat)
	}

	packetWriter, exists := h.writers[identifier]
	if !exists {
		packetWriter, err = h.newPacketWriter(identifier, p.Metadata().InterfaceIndex, ad)
		if err != nil {
			return err
		}
		h.writers[identifier] = packetWriter
	} else {
		// We already have a writer, check if we need to update it.
		// If we're outputting to a directory, then we have a writer for each interface, so there's no need to update it,
		// And we only need to add interfaces for pcapng format.
		if !h.isDir && h.outputFormat == capperpb.PcapOutputFormat_OUTPUT_FORMAT_PCAPNG {
			if _, configured := h.interfaceConfigured[p.Metadata().InterfaceIndex]; !configured {
				ngWriter := packetWriter.(*capture.PcapNgWriter)
				_, err := ngWriter.AddInterface(ad.IfaceName, p.Metadata().InterfaceIndex, layers.LinkType(ad.LinkType))
				if err != nil {
					return err
				}
				h.interfaceConfigured[p.Metadata().InterfaceIndex] = struct{}{}
			}
		}
	}
	return packetWriter.WritePacket(p.Metadata().CaptureInfo, p.Data())
}

func (h *outputFileHandler) newPacketWriter(identifier string, interfaceIndex int, ad *capperpb.AncillaryPacketData) (capture.PacketWriter, error) {
	var packetWriter capture.PacketWriter
	var w io.Writer
	if h.isDir {
		f, err := os.Create(filepath.Join(h.outputPath, identifier))
		if err != nil {
			return nil, fmt.Errorf("error opening output: %w", err)
		}
		h.closers = append(h.closers, f)
		w = f
	} else if h.outputPath == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(h.outputPath)
		if err != nil {
			return nil, fmt.Errorf("error opening output: %w", err)
		}
		h.closers = append(h.closers, f)
		w = f
	}

	switch h.outputFormat {
	case capperpb.PcapOutputFormat_OUTPUT_FORMAT_PCAPNG:
		var err error
		packetWriter, err = capture.NewPcapNgWriter(
			w, h.linkType, h.snaplen,
			ad.GetIfaceName(), interfaceIndex,
			ad.GetHardware(), ad.GetOperatingSystem(),
			ad.GetNodeName(),
		)
		if err != nil {
			return nil, err
		}
		h.interfaceConfigured[interfaceIndex] = struct{}{}
	case capperpb.PcapOutputFormat_OUTPUT_FORMAT_PCAP:
		fallthrough
	default:
		packetWriter = capture.NewPcapWriter(w, h.linkType, h.snaplen)
	}
	return packetWriter, nil
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
