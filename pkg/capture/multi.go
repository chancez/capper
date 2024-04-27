package capture

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/jonboulle/clockwork"
)

// StartMulti starts a packet capture on each of the specified interfaces.
func StartMulti(ctx context.Context, log *slog.Logger, ifaces []string, conf Config, handler PacketHandler) error {
	// If we don't have multiple interfaces, just delegate to Run()
	if len(ifaces) < 2 {
		// Run() handles empty iface by picking one automatically if it's not specified.
		iface := ""
		if len(ifaces) == 1 {
			iface = ifaces[0]
		}
		return Start(ctx, log, iface, conf, handler)
	}
	clock := clockwork.NewRealClock()

	outerStart := clock.Now()
	outerCount := uint64(0)

	var sources []NamedPacketSource
	// We will get the linkType from the first handle, and use that for the
	// handler provided.
	var handlerLinkType layers.LinkType

	log.Debug("starting sub-captures", "interfaces", ifaces)
	for _, iface := range ifaces {
		start := clock.Now()
		// TODO: Count packets for the sub-captures.

		if iface == "" {
			var err error
			iface, err = getInterface(conf.Netns)
			if err != nil {
				return fmt.Errorf("error getting interface: %w", err)
			}
		}

		handle, err := NewLiveHandle(iface, conf.Netns, conf.Filter, conf.Snaplen, conf.Promisc, conf.BufferSize)
		if err != nil {
			return fmt.Errorf("error creating handle: %w", err)
		}
		log.Debug("sub-capture started", "interface", iface, "link_type", handle.LinkType(), "num_packets", conf.NumPackets, "duration", conf.CaptureDuration)

		// Set the linkType for our PacketHandler to the linkType of the first
		// handle
		if handlerLinkType == layers.LinkTypeNull {
			handlerLinkType = handle.LinkType()
			log.Debug("using first handles linkType", "link_type", handlerLinkType)
		}

		sources = append(sources, NamedPacketSource{
			Name: "iface-" + iface,
			// We use the original handle LinkType in the PacketSource
			PacketSource: gopacket.NewPacketSource(handle, handle.LinkType()),
		})

		defer func() {
			log.Debug("sub-capture finished", "interface", iface, "capture_duration", clock.Since(start))
			handle.Close()
		}()
	}

	log.Info("multi capture started", "interfaces", ifaces, "link_type", handlerLinkType)
	defer func() {
		defer log.Info("multi capture finished", "interfaces", ifaces, "packets", outerCount, "capture_duration", clock.Since(outerStart))
	}()

	packetsCtx := ctx
	if conf.CaptureDuration > 0 {
		var packetsCancel context.CancelFunc
		packetsCtx, packetsCancel = context.WithTimeout(ctx, conf.CaptureDuration)
		defer packetsCancel()
	}

	// Drain at 10 packets, or NumPackets if it's lower than 10
	heapDrainThreshold := 10
	if conf.NumPackets > 0 && conf.NumPackets < uint64(heapDrainThreshold) {
		heapDrainThreshold = int(conf.NumPackets)
	}
	flushInterval := 2 * time.Second
	// Scale the merge buffer based on the number of captures
	mergeBufferSize := 10 * len(sources)
	merger := NewPacketMerger(log, sources, heapDrainThreshold, flushInterval, mergeBufferSize, 0)
	for packet := range merger.PacketsCtx(packetsCtx) {
		if err := handler.HandlePacket(handlerLinkType, packet); err != nil {
			return err
		}
		outerCount++
		if conf.NumPackets != 0 && outerCount >= conf.NumPackets {
			log.Debug("reached num_packets limit, stopping capture", "num_packets", conf.NumPackets)
			break
		}
	}
	return nil
}
