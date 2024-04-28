package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
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
		staticPeers, err := cmd.Flags().GetStringSlice("static-peers")
		if err != nil {
			return err
		}
		peerDnsQuery, err := cmd.Flags().GetString("dns-srv-peers")
		if err != nil {
			return err
		}
		logLevel, err := cmd.Flags().GetString("log-level")
		if err != nil {
			return err
		}
		log, err := newLevelLogger(logLevel)
		if err != nil {
			return err
		}
		return runGateway(cmd.Context(), log, listen, staticPeers, peerDnsQuery)
	},
}

func init() {
	rootCmd.AddCommand(gatewayCmd)
	gatewayCmd.Flags().String("listen-address", "127.0.0.1:48999", "Gateway listen address")
	gatewayCmd.Flags().StringSlice("static-peers", []string{}, "List of peers")
	gatewayCmd.Flags().String("dns-srv-peers", "", "Specify a DNS SRV query for obtaining the list of peers")
	gatewayCmd.Flags().String("log-level", "info", "Configure the log level.")
}

func runGateway(ctx context.Context, logger *slog.Logger, listen string, staticPeers []string, peerDnsQuery string) error {
	logger = logger.With("component", "gateway")

	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	peerManager := NewPeerManager(logger.With("subsystem", "peer-manager"), peerDnsQuery, 5*time.Second)
	gatewaySrv := newGRPCServer(logger, &gateway{
		clock:       clockwork.NewRealClock(),
		staticPeers: staticPeers,
		log:         logger,
		connTimeout: 5 * time.Second,
		peerManager: peerManager,
	})

	eg, ctx := errgroup.WithContext(ctx)

	logger.Info("starting peer manager", "query", peerDnsQuery)
	eg.Go(func() error {
		return peerManager.Start(ctx)
	})

	logger.Info("starting gateway", "listen-address", listen, "peers", staticPeers)
	eg.Go(func() error {
		if err := gatewaySrv.Serve(lis); err != nil {
			return fmt.Errorf("failed to serve: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}

	return nil
}

type gateway struct {
	capperpb.UnimplementedCapperServer
	clock       clockwork.Clock
	log         *slog.Logger
	staticPeers []string
	connTimeout time.Duration
	peerManager *PeerManager
}

func (s *gateway) Capture(req *capperpb.CaptureRequest, stream capperpb.Capper_CaptureServer) error {
	ctx := stream.Context()

	dynamicPeers := s.peerManager.Peers()

	peers := make([]string, 0, len(s.staticPeers)+len(dynamicPeers))
	peers = append(peers, s.staticPeers...)
	peers = append(peers, dynamicPeers...)

	if len(peers) == 0 {
		s.log.Error("no peers found")
		return status.Error(codes.Internal, "no peers")
	} else {
		s.log.Debug("found peers", "peers", peers)
	}

	var sources []capture.NamedPacketSource
	var linkType layers.LinkType
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
		peerStream, err := c.Capture(ctx, req)
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

		// Unset, use the first reader's link type
		if linkType == layers.LinkTypeNull {
			linkType, err = reader.LinkType()
			if err != nil {
				return err
			}
			s.log.Debug("using first streams linkType", "link_type", linkType)

			header := metadata.Pairs("link_type", strconv.Itoa(int(linkType)))
			err = grpc.SendHeader(ctx, header)
			if err != nil {
				return status.Errorf(codes.Internal, "error sending header: %s", err)
			}
		}
		sources = append(sources, capture.NamedPacketSource{
			Name:         peer,
			PacketSource: gopacket.NewPacketSource(reader, linkType),
		})
	}

	s.log.Debug("starting packet merger")
	heapDrainThreshold := 10 * len(peers)
	flushInterval := time.Duration(2*len(peers)) * time.Second
	mergeBufferSize := len(peers)
	// merge the contents of the sources
	merger := capture.NewPacketMerger(s.log, sources, heapDrainThreshold, flushInterval, mergeBufferSize, 0)
	handler, err := newStreamPacketHandler(linkType, uint32(req.GetSnaplen()), stream)
	if err != nil {
		return err
	}

	s.log.Debug("receiving packets from clients")
	for packet := range merger.PacketsCtx(ctx) {
		// TODO: stream handler does not use link type and we have multiple link
		// types due to multiple handles being merged
		if err := handler.HandlePacket(packet); err != nil {
			return err
		}
	}
	return nil
}

type PeerManager struct {
	clock clockwork.Clock
	log   *slog.Logger

	peersMu sync.Mutex
	peers   []string

	checkInterval time.Duration
	query         string
}

func NewPeerManager(log *slog.Logger, query string, checkInterval time.Duration) *PeerManager {
	return &PeerManager{
		clock:         clockwork.NewRealClock(),
		log:           log,
		query:         query,
		checkInterval: checkInterval,
	}
}

func (pm *PeerManager) Start(ctx context.Context) error {
	ticker := pm.clock.NewTicker(pm.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.Chan():
			var peers []string
			_, records, err := net.DefaultResolver.LookupSRV(ctx, "", "", pm.query)
			if err != nil {
				pm.log.Error("error resolving peers", "error", err)
				continue
			}
			for _, srv := range records {
				p := fmt.Sprintf("%s:%d", srv.Target, srv.Port)
				peers = append(peers, p)
			}

			if !slices.Equal(pm.peers, peers) {
				pm.peersMu.Lock()
				pm.log.Debug("updating peers list", "old", pm.peers, "new", peers)
				pm.peers = peers
				pm.peersMu.Unlock()
			}
		}
	}
}

func (pm *PeerManager) Peers() []string {
	pm.peersMu.Lock()
	defer pm.peersMu.Unlock()
	return pm.peers
}
