package cmd

import (
	"container/heap"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/chancez/capper/pkg/minheap"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// gatewayCmd represents the gateway command
var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Starts a capture gateway",
	RunE: func(cmd *cobra.Command, args []string) error {
		listen, err := cmd.Flags().GetString("listen-address")
		if err != nil {
			return err
		}
		peers, err := cmd.Flags().GetStringSlice("peers")
		if err != nil {
			return err
		}
		return runGateway(listen, peers)
	},
}

func init() {
	rootCmd.AddCommand(gatewayCmd)
	gatewayCmd.Flags().String("listen-address", "127.0.0.1:48999", "Gateway listen address")
	gatewayCmd.Flags().StringSlice("peers", []string{}, "List of peers")
}

func runGateway(listen string, peers []string) error {
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	logger := slog.Default().With("component", "gateway")
	slog.SetLogLoggerLevel(slog.LevelDebug)

	s := newGRPCServer(logger, &gateway{
		clock:       clockwork.NewRealClock(),
		log:         logger,
		peers:       peers,
		connTimeout: 5 * time.Second,
	})

	slog.Info("starting gateway", "listen-address", listen, "peers", peers)
	if err := s.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}

type gateway struct {
	capperpb.UnimplementedCapperServer
	clock       clockwork.Clock
	log         *slog.Logger
	peers       []string
	connTimeout time.Duration
}

func (s *gateway) StreamCapture(req *capperpb.CaptureRequest, stream capperpb.Capper_StreamCaptureServer) error {
	ctx := stream.Context()

	var peers []string
	for _, p := range s.peers {
		if strings.HasPrefix(p, "dnssrv+") {
			query := strings.TrimPrefix(p, "dnssrv+")
			_, records, err := net.DefaultResolver.LookupSRV(ctx, "", "", query)
			if err != nil {
				return status.Errorf(codes.Internal, "error resolving peers: %s", err)
			}
			for _, srv := range records {
				p = fmt.Sprintf("%s:%d", srv.Target, srv.Port)
			}
		}
		peers = append(peers, p)
	}

	var sources []NamedPacketSource
	for _, peer := range peers {
		s.log.Debug("connecting to peer", "peer", peer)
		connCtx := ctx
		if s.connTimeout != 0 {
			var connCancel context.CancelFunc
			connCtx, connCancel = context.WithTimeout(ctx, s.connTimeout)
			defer connCancel()
		}
		conn, err := grpc.DialContext(connCtx, peer, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return fmt.Errorf("error connecting to peer: %w", err)
		}
		defer conn.Close()
		c := capperpb.NewCapperClient(conn)

		s.log.Debug("starting stream", "peer", peer)
		peerStream, err := c.StreamCapture(ctx, req)
		if err != nil {
			return fmt.Errorf("error creating stream: %w", err)
		}

		// Begins reading from the stream
		s.log.Debug("reading from client stream", "peer", peer)
		reader, err := newClientStreamReader(peerStream)
		if err != nil {
			return err
		}
		defer reader.Close()

		sources = append(sources, NamedPacketSource{
			Name:         peer,
			PacketSource: gopacket.NewPacketSource(reader, reader.LinkType()),
		})
	}

	s.log.Debug("starting packet merger")
	heapDrainThreshold := 10 * len(peers)
	flushInterval := time.Duration(2*len(peers)) * time.Second
	mergeBufferSize := len(peers)
	// merge the contents of the sources
	merger := NewPacketMerger(s.log, sources, heapDrainThreshold, flushInterval, mergeBufferSize, 0)
	handler := newStreamPacketHandler(uint32(req.GetSnaplen()), layers.LinkTypeEthernet, stream)

	s.log.Debug("receiving packets from clients")
	for packet := range merger.PacketsCtx(ctx) {
		if err := handler.HandlePacket(packet); err != nil {
			return err
		}
	}
	return nil
}

type PacketSource interface {
	PacketsCtx(ctx context.Context) chan gopacket.Packet
}

// PacketMerger takes multiple PacketSources and combines them
type PacketMerger struct {
	clock clockwork.Clock
	log   *slog.Logger

	// store our packets in a minheap, ordering values by their timestamp.
	// popping elements will return the packet with the lowest timestamp,
	// helping ensure we send packets in-order by timestamp.
	packetHeap minheap.PacketHeap

	heapDrainThreshold int
	flushInterval      time.Duration
	mergeBufferSize    int
	outputBufferSize   int
	exitFlushTimeout   time.Duration

	sources []NamedPacketSource
	output  chan gopacket.Packet
}

type NamedPacketSource struct {
	Name string
	PacketSource
}

func NewPacketMerger(log *slog.Logger, sources []NamedPacketSource, heapDrainThreshold int, flushInterval time.Duration, mergeBufferSize int, outputBufferSize int) *PacketMerger {
	return &PacketMerger{
		clock:              clockwork.NewRealClock(),
		log:                log.With("subsystem", "packet-merger"),
		heapDrainThreshold: heapDrainThreshold,
		flushInterval:      flushInterval,
		mergeBufferSize:    mergeBufferSize,
		outputBufferSize:   outputBufferSize,
		exitFlushTimeout:   5 * time.Second,
		sources:            sources,
	}
}

func (pm *PacketMerger) PacketsCtx(ctx context.Context) chan gopacket.Packet {
	if pm.output == nil {
		pm.output = make(chan gopacket.Packet, pm.outputBufferSize)
		go pm.run(ctx)
	}
	return pm.output
}

func (pm *PacketMerger) sendPacket(ctx context.Context) {
	// helper to send a packet if one exists, blocking until once does exist or
	// the context is cancelled
	p := heap.Pop(&pm.packetHeap).(gopacket.Packet)
	select {
	case pm.output <- p:
	case <-ctx.Done():
	}
}

func (pm *PacketMerger) drainHeap(ctx context.Context, timeout time.Duration) int {
	// flush the entire heap, with a timeout for flushing
	sent := 0
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for len(pm.packetHeap) > 0 {
		pm.sendPacket(ctx)
		sent++
	}
	return sent
}

func (pm *PacketMerger) run(ctx context.Context) {
	pm.log.Debug("merger started")

	defer func() {
		pm.log.Debug("merger finished")
		close(pm.output)
	}()

	// Use a buffered channel so that we can continue to receive packets from sources while merging
	sourcePackets := make(chan gopacket.Packet, pm.mergeBufferSize)

	// start a consumer goroutine that buffers and merges the packets from each
	// source before sending them to the output
	var consumerWg sync.WaitGroup
	consumerWg.Add(1)
	go func() {
		pm.log.Debug("merger consumer started")
		defer func() {
			pm.log.Debug("merger consumer finished")
			consumerWg.Done()
		}()

		ticker := pm.clock.NewTicker(pm.flushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// drain the entire heap
				sent := pm.drainHeap(ctx, pm.exitFlushTimeout)
				pm.log.Debug("merger consumer cancelled: flushed packets", "num_packets", sent, "flushInterval", pm.flushInterval, "heapSize", len(pm.packetHeap))
				return
			case p, ok := <-sourcePackets:
				if !ok {
					// drain the entire heap
					sent := pm.drainHeap(ctx, pm.exitFlushTimeout)
					pm.log.Debug("merger consumer source closed: flushed packets", "num_packets", sent, "flushInterval", pm.flushInterval, "heapSize", len(pm.packetHeap))
					return
				}

				heap.Push(&pm.packetHeap, p)
				sent := 0
				// Buffer some packets in case we need to re-order, so only packets
				// send after we've gotten to the heapDrainThreshold, and always keep some
				// buffered.
				// If there's a long delay, the ticker will flush some of the pending
				// packets.
				for len(pm.packetHeap) >= pm.heapDrainThreshold {
					pm.sendPacket(ctx)
					sent++
				}
				if sent > 0 {
					// Reset the ticker if we recently sent new packets
					ticker.Reset(pm.flushInterval)
				}
			case <-ticker.Chan():
				// Send 1/2 the heap if we haven't sent anything in a while
				sent := 0
				for ; sent < len(pm.packetHeap)/2 || len(pm.packetHeap) == 1; sent++ {
					pm.sendPacket(ctx)
				}
				pm.log.Debug("reached flushInterval: flushed packets", "num_packets", sent, "flushInterval", pm.flushInterval, "heapSize", len(pm.packetHeap))
			}
		}
	}()

	pm.log.Debug("starting merger producers")
	var sourcesWg sync.WaitGroup
	for _, src := range pm.sources {
		src := src
		// start a producer goroutine for each source
		sourcesWg.Add(1)
		go func() {
			pm.log.Debug("merger producer started", "source", src.Name)
			defer func() {
				pm.log.Debug("merger producer finished", "source", src.Name)
				sourcesWg.Done()
			}()

			// send all the packets coming from this source to the merger/consumer goroutine
			for packet := range src.PacketsCtx(ctx) {
				select {
				case <-ctx.Done():
					return
				case sourcePackets <- packet:
				}
			}
		}()
	}

	pm.log.Debug("waiting for sources to stop")
	// After the the input sources are finished, tell the consumer to return by
	// closing sourcesPackets
	sourcesWg.Wait()
	close(sourcePackets)

	pm.log.Debug("waiting for consumer to stop")
	// wait for the consumer to complete
	consumerWg.Wait()
}
