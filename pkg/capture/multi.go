package capture

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/jonboulle/clockwork"
)

type MultiCapture struct {
	log   *slog.Logger
	clock clockwork.Clock
	conf  Config

	ifaces  []*capperpb.CaptureInterface
	handles []*pcap.Handle
	sources []NamedPacketSource
}

func NewMulti(ctx context.Context, log *slog.Logger, ifaces []string, netns string, conf Config) (*MultiCapture, error) {
	clock := clockwork.NewRealClock()
	var handles []*pcap.Handle
	var captureInterfaces []*capperpb.CaptureInterface
	var sources []NamedPacketSource
	// We will get the linkType from the first handle, and use that for the
	// handler provided.
	var handlerLinkType layers.LinkType

	if len(ifaces) == 0 {
		ifaces = []string{""}
	}
	log.Debug("creating handles", "interfaces", ifaces)
	for _, ifaceName := range ifaces {
		// TODO: Count packets for the sub-captures.
		iface, err := getInterface(ifaceName, netns)
		if err != nil {
			return nil, fmt.Errorf("error getting interface: %w", err)
		}

		// TODO: use same linkType on all handles
		handle, err := NewLiveHandle(iface.Name, netns, conf.Filter, conf.Snaplen, conf.Promisc, conf.BufferSize)
		if err != nil {
			return nil, fmt.Errorf("error creating handle: %w", err)
		}
		log.Debug("handle created", "interface", iface.Name, "link_type", handle.LinkType())

		// Set the linkType for our PacketHandler to the linkType of the first
		// handle
		if handlerLinkType == layers.LinkTypeNull {
			handlerLinkType = handle.LinkType()
			log.Debug("using first handles linkType", "link_type", handlerLinkType)
		}

		captureInterfaces = append(captureInterfaces, iface)
		handles = append(handles, handle)

		sources = append(sources, NamedPacketSource{
			Name: "iface-" + iface.Name,
			// We use the original handle LinkType in the PacketSource
			PacketSource: gopacket.NewPacketSource(handle, handlerLinkType),
		})

	}

	return &MultiCapture{
		log:     log,
		clock:   clock,
		conf:    conf,
		ifaces:  captureInterfaces,
		handles: handles,
		sources: sources,
	}, nil
}

func (c *MultiCapture) LinkType() layers.LinkType {
	return c.handles[0].LinkType()
}

func (c *MultiCapture) Interfaces() []*capperpb.CaptureInterface {
	return c.ifaces
}

func (c *MultiCapture) Start(ctx context.Context, handler PacketHandler) error {
	clock := clockwork.NewRealClock()

	start := clock.Now()
	count := uint64(0)

	c.log.Info("multi capture started", "interfaces", c.ifaces, "link_type", c.LinkType())
	defer func() {
		err := handler.Flush()
		if err != nil {
			c.log.Error("error flushing handler", "interfaces", c.ifaces, "error", err)
		}
		c.log.Info("multi capture finished", "interfaces", c.ifaces, "packets", count, "capture_duration", clock.Since(start))
	}()

	packetsCtx := ctx
	if c.conf.CaptureDuration > 0 {
		var packetsCancel context.CancelFunc
		packetsCtx, packetsCancel = context.WithTimeout(ctx, c.conf.CaptureDuration)
		defer packetsCancel()
	}

	// Drain at 10 packets, or NumPackets if it's lower than 10
	heapDrainThreshold := 10
	if c.conf.NumPackets > 0 && c.conf.NumPackets < uint64(heapDrainThreshold) {
		heapDrainThreshold = int(c.conf.NumPackets)
	}
	flushInterval := 2 * time.Second
	// Scale the merge buffer based on the number of captures
	mergeBufferSize := 10 * len(c.sources)
	merger := NewPacketMerger(c.log, c.sources, heapDrainThreshold, flushInterval, mergeBufferSize, 0)
	for packet := range merger.PacketsCtx(packetsCtx) {
		if err := handler.HandlePacket(packet); err != nil {
			return err
		}
		count++
		if c.conf.NumPackets != 0 && count >= c.conf.NumPackets {
			c.log.Debug("reached num_packets limit, stopping capture", "num_packets", c.conf.NumPackets)
			break
		}
	}
	return nil
}

func (c *MultiCapture) Close() {
	for _, handle := range c.handles {
		handle.Close()
	}
}
