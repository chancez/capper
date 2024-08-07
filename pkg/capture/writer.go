package capture

import (
	"fmt"
	"io"
	"strconv"
	"strings"

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
	snaplen  uint32
	os       string

	interfaceToID map[CaptureInterface]int
}

func NewPcapNgWriter(w io.Writer, iface CaptureInterface, snaplen uint32, hardware, os string) (*PcapNgWriter, error) {
	interfaceToID := make(map[CaptureInterface]int)
	intf := pcapgo.NgInterface{
		Name:        iface.Name,
		Index:       iface.Index,
		LinkType:    iface.LinkType,
		SnapLength:  snaplen,
		OS:          os,
		Description: interfaceDescription(iface),
	}
	interfaceToID[iface] = 0

	ngOpts := pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Hardware:    hardware,
			OS:          os,
			Application: "capper",
		},
		CaptureInfoToID: func(ci gopacket.CaptureInfo, data []byte) (id int, ok bool) {
			ad, err := GetCapperAncillaryData(ci)
			if err != nil {
				return -1, false
			}
			iface := CaptureInterface{
				Name:            ad.IfaceName,
				Index:           ci.InterfaceIndex,
				Hostname:        ad.NodeName,
				Netns:           ad.Netns,
				NetnsInode:      ad.NetnsInode,
				LinkType:        layers.LinkType(ad.LinkType),
				K8sPod:          ad.K8SPodName,
				K8sPodNamespace: ad.K8SPodNamespace,
			}
			id, ok = interfaceToID[iface]
			return id, ok
		},
	}
	ngWriter, err := pcapgo.NewNgWriterInterface(w, intf, ngOpts)
	if err != nil {
		return nil, err
	}
	return &PcapNgWriter{
		ngWriter:      ngWriter,
		snaplen:       snaplen,
		os:            os,
		interfaceToID: interfaceToID,
	}, nil
}

func (w *PcapNgWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	return w.ngWriter.WritePacket(ci, data)
}

func (w *PcapNgWriter) Flush() error {
	return w.ngWriter.Flush()
}

func (w *PcapNgWriter) AddInterface(iface CaptureInterface) (int, error) {
	id, err := w.ngWriter.AddInterface(pcapgo.NgInterface{
		Name:        iface.Name,
		Index:       int(iface.Index),
		LinkType:    iface.LinkType,
		SnapLength:  w.snaplen,
		OS:          w.os,
		Description: interfaceDescription(iface),
	})
	if err == nil {
		w.interfaceToID[iface] = id
	}
	return id, err
}

func interfaceDescription(i CaptureInterface) string {
	var b strings.Builder
	b.WriteString("interface: ")
	b.WriteString(i.Name)
	b.WriteString(" index: ")
	b.WriteString(strconv.Itoa(i.Index))
	b.WriteString(" hostname: ")
	b.WriteString(i.Hostname)
	if i.K8sPod != "" {
		b.WriteString(" pod: ")
		b.WriteString(i.K8sPodNamespace)
		b.WriteString("/")
		b.WriteString(i.K8sPod)
	} else if i.Netns != "" {
		b.WriteString(" netns: ")
		b.WriteString(i.Netns)
	}

	return b.String()
}
