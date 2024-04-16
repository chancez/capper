package cmd

import (
	"container/heap"
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/chancez/capper/pkg/capture"
	"github.com/chancez/capper/pkg/minheap"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	gatewayCmd.Flags().String("listen-address", "127.0.0.1:8080", "Gateway listen address")
	gatewayCmd.Flags().StringSlice("peers", []string{}, "List of peers")
}

func runGateway(listen string, peers []string) error {
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	logger := slog.Default()
	slog.SetLogLoggerLevel(slog.LevelDebug)

	s := newGRPCServer(logger, &gateway{
		clock: clockwork.NewRealClock(),
		log:   logger,
		peers: peers,
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
	streamCtx := stream.Context()
	eg, ctx := errgroup.WithContext(streamCtx)

	drainHeapSize := 10 * len(s.peers)
	flushInterval := time.Duration(2*len(s.peers)) * time.Second

	// Use a buffered channel so that we can continue to receive packets from peers while merging
	peerPackets := make(chan gopacket.Packet, len(s.peers))

	// start a consumer goroutine that buffers and merges the packets from each
	// peer before sending them to the client
	eg.Go(func() error {
		// sends packets over the server stream
		streamHandler := newStreamPacketHandler(uint32(req.GetSnaplen()), layers.LinkTypeEthernet, stream)
		// store our packets in a minheap, ordering values by their timestamp.
		// popping elements will return the packet with the lowest timestamp,
		// helping ensure we send packets in-order by timestamp.
		var packetHeap minheap.PacketHeap

		sendPacket := func() error {
			p := heap.Pop(&packetHeap).(gopacket.Packet)
			return streamHandler.HandlePacket(p)
		}

		ticker := time.NewTicker(flushInterval)
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case p, ok := <-peerPackets:
				if !ok {
					// flush the entire heap
					for len(packetHeap) > 0 {
						if err := sendPacket(); err != nil {
							return err
						}
					}
					return nil
				}
				heap.Push(&packetHeap, p)
				sent := 0
				// Buffer some packets in case we need to re-order, so only send after
				// we've gotten to the drainHeapSize.
				// If there's a long delay, the ticker will flush some of the pending packets
				for len(packetHeap) >= drainHeapSize {
					if err := sendPacket(); err != nil {
						return err
					}
					sent++
				}
				if sent > 0 {
					s.log.Debug("reached drainHeapSize: flushed packets", "num_packets", sent, "drainHeapSize", drainHeapSize, "heapSize", len(packetHeap))
					// Reset the ticker if we recently sent new packets
					ticker.Reset(flushInterval)
				}
			case <-ticker.C:
				// Send 1/2 the heap if we haven't sent anything in a while
				sent := 0
				for ; sent < len(packetHeap)/2 || len(packetHeap) == 1; sent++ {
					if err := sendPacket(); err != nil {
						return err
					}
				}
				s.log.Debug("reached flushInterval: flushed packets", "num_packets", sent, "flushInterval", flushInterval, "heapSize", len(packetHeap))
			}
		}
	})

	// called in each peer producer goroutine to send packets to the consumer
	peerPacketHandler := capture.PacketHandlerFunc(func(p gopacket.Packet) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case peerPackets <- p:
		}
		return nil
	})

	var peerWg sync.WaitGroup
	for _, peer := range s.peers {
		// start a producer goroutine for each peer
		peerWg.Add(1)
		eg.Go(func() error {
			defer peerWg.Done()
			s.log.Debug("connecting to peer", "peer", peer)
			connCtx, connCancel := context.WithTimeout(ctx, s.connTimeout)
			conn, err := grpc.DialContext(connCtx, peer, grpc.WithTransportCredentials(insecure.NewCredentials()))
			connCancel()
			if err != nil {
				return fmt.Errorf("error connecting to peer: %w", err)
			}
			c := capperpb.NewCapperClient(conn)

			s.log.Debug("starting stream", "peer", peer)
			peerStream, err := c.StreamCapture(ctx, req)
			if err != nil {
				return fmt.Errorf("error creating stream: %w", err)
			}
			defer s.log.Debug("client stream ended", "peer", peer)

			return handleClientStream(ctx, peerPacketHandler, peerStream)
		})
	}

	go func() {
		// After the peer connections are finished, tell the consumer to return by
		// closing peerPackets
		peerWg.Wait()
		close(peerPackets)
	}()

	fmt.Println("waiting for go routines to stop")
	if err := eg.Wait(); err != nil {
		return fmt.Errorf("error occurred while querying peers: %w", err)
	}
	return nil
}
