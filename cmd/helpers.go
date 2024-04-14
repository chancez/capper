package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/jonboulle/clockwork"
)

func newHandle(device string, filter string, snaplen int, promisc bool) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(device)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(snaplen); err != nil {
		return nil, fmt.Errorf("error setting snaplen on handle: %w", err)
	}

	if err := inactive.SetPromisc(promisc); err != nil {
		return nil, fmt.Errorf("error setting promiscuous mode on handle: %w", err)
	}

	if err := inactive.SetTimeout(time.Second); err != nil {
		return nil, fmt.Errorf("error setting timeout on handle: %w", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("error activating handle: %w", err)
	}

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return nil, fmt.Errorf("error setting filter on handle: %w", err)
		}
	}
	return handle, nil
}

type packetCapture struct {
	clock   clockwork.Clock
	log     *slog.Logger
	handler packetHandler
}

type packetHandler interface {
	HandlePacket(*pcap.Handle, gopacket.Packet) error
}

type packetHandlerFunc func(*pcap.Handle, gopacket.Packet) error

func (f packetHandlerFunc) HandlePacket(h *pcap.Handle, p gopacket.Packet) error {
	return f(h, p)
}

func newPacketCapture(log *slog.Logger, handler packetHandler) *packetCapture {
	return &packetCapture{
		clock:   clockwork.NewRealClock(),
		log:     log,
		handler: handler,
	}
}

func (c *packetCapture) Run(ctx context.Context, device string, filter string, snaplen int, promisc bool, numPackets uint64, captureDuration time.Duration) error {
	start := c.clock.Now()
	count := uint64(0)
	c.log.Debug("starting capture", "num_packets", numPackets, "duration", captureDuration)

	handle, err := newHandle(device, filter, snaplen, promisc)
	if err != nil {
		return fmt.Errorf("error creating handle: %w", err)
	}
	defer func() {
		c.log.Debug("capture finished", "packets", count, "capture_duration", c.clock.Since(start))
		handle.Close()
	}()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.PacketsCtx(ctx) {
		err := c.handler.HandlePacket(handle, packet)
		if err != nil {
			return fmt.Errorf("error handling packet: %w", err)
		}
		count++
		if numPackets != 0 && count >= numPackets {
			c.log.Debug("reached num_packets limit, stopping capture", "num_packets", numPackets)
			break
		}

		if captureDuration != 0 && c.clock.Since(start) >= captureDuration {
			c.log.Debug("hit duration limit, stopping capture", "duration", captureDuration)
			break
		}
	}
	return nil
}

type packetWriterHandler struct {
	pcapWriter    *pcapgo.Writer
	headerWritten bool
}

func newPacketWriterHandler(w io.Writer) *packetWriterHandler {
	return &packetWriterHandler{pcapWriter: pcapgo.NewWriter(w)}
}

func (pwh *packetWriterHandler) HandlePacket(h *pcap.Handle, p gopacket.Packet) error {
	if !pwh.headerWritten {
		if err := pwh.pcapWriter.WriteFileHeader(uint32(h.SnapLen()), h.LinkType()); err != nil {
			return fmt.Errorf("error writing file header: %w", err)
		}
		pwh.headerWritten = true
	}

	if err := pwh.pcapWriter.WritePacket(p.Metadata().CaptureInfo, p.Data()); err != nil {
		return fmt.Errorf("error writing packet: %w", err)
	}
	return nil
}

var packetPrinterHandler = packetHandlerFunc(func(h *pcap.Handle, p gopacket.Packet) error {
	fmt.Println(p)
	return nil
})

func chainPacketHandlers(handlers ...packetHandler) packetHandler {
	return packetHandlerFunc(func(h *pcap.Handle, p gopacket.Packet) error {
		for _, handler := range handlers {
			err := handler.HandlePacket(h, p)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
