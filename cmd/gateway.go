package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	mapset "github.com/deckarep/golang-set/v2"
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

	pmLogger := logger.With("subsystem", "peer-manager")
	peerManager := NewPeerManager(pmLogger, peerDnsQuery, 5*time.Second)
	clientPool := NewPeerClientConnPool(logger.With("subsystem", "client-pool"), 5*time.Second)

	peerManager.checkCallback = func(removed, added []string) {
		for _, peer := range removed {
			err := clientPool.Close(peer)
			if err != nil {
				pmLogger.Error("unable to closing connection to peer", "peer", peer, "err", err)
			}
		}
		for _, peer := range added {
			_, err := clientPool.Client(ctx, peer)
			if err != nil {
				pmLogger.Error("unable to connect to peer", "peer", peer, "err", err)
			}
		}
	}

	gatewaySrv := newGRPCServer(logger, &gateway{
		clock:       clockwork.NewRealClock(),
		staticPeers: staticPeers,
		log:         logger,
		peerManager: peerManager,
		clientPool:  clientPool,
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
	peerManager *PeerManager
	clientPool  *PeerClientConnPool
}

func (s *gateway) Capture(req *capperpb.CaptureRequest, stream capperpb.Capper_CaptureServer) error {
	ctx := stream.Context()

	dynamicPeers := s.peerManager.Peers()

	peers := make([]string, 0, len(s.staticPeers)+len(dynamicPeers))
	peers = append(peers, s.staticPeers...)
	peers = append(peers, dynamicPeers...)

	if len(peers) == 0 {
		s.log.Error("no peers")
		return status.Error(codes.Internal, "no peers")
	}

	s.log.Debug("found peers", "peers", peers)

	var sources []capture.NamedPacketSource
	var linkType layers.LinkType
	for _, peer := range peers {
		conn, err := s.clientPool.Client(ctx, peer)
		if err != nil {
			return err
		}

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

type PeerClientConnPool struct {
	log         *slog.Logger
	connTimeout time.Duration

	mu          sync.Mutex
	clientConns map[string]*grpc.ClientConn
}

func NewPeerClientConnPool(log *slog.Logger, connTimeout time.Duration) *PeerClientConnPool {
	return &PeerClientConnPool{
		log:         log,
		connTimeout: connTimeout,
		clientConns: make(map[string]*grpc.ClientConn),
	}
}

func (pcm *PeerClientConnPool) Client(ctx context.Context, peer string) (*grpc.ClientConn, error) {
	pcm.mu.Lock()
	defer pcm.mu.Unlock()
	conn, ok := pcm.clientConns[peer]
	if !ok {
		pcm.log.Debug("connecting to peer", "peer", peer)
		connCtx := ctx
		if pcm.connTimeout != 0 {
			var connCancel context.CancelFunc
			connCtx, connCancel = context.WithTimeout(ctx, pcm.connTimeout)
			defer connCancel()
		}
		var err error
		conn, err = grpc.DialContext(connCtx, peer, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("error connecting to peer: %w", err)
		}
		pcm.log.Info("established connection to peer", "peer", peer)
		pcm.clientConns[peer] = conn
	}
	return conn, nil
}

func (pcm *PeerClientConnPool) Close(peer string) error {
	pcm.mu.Lock()
	defer pcm.mu.Unlock()
	conn, ok := pcm.clientConns[peer]
	if !ok {
		return nil
	}
	pcm.log.Debug("closing connection to peer", "peer", peer)
	return conn.Close()
}

func (pcm *PeerClientConnPool) CloseAll(peer string) error {
	pcm.mu.Lock()
	defer pcm.mu.Unlock()
	var errs []error
	for _, conn := range pcm.clientConns {
		errs = append(errs, conn.Close())
	}
	return errors.Join(errs...)
}

type PeerManager struct {
	clock clockwork.Clock
	log   *slog.Logger

	peersMu sync.Mutex
	peers   mapset.Set[string]

	checkInterval time.Duration
	checkCallback func(removed, added []string)
	query         string
}

func NewPeerManager(log *slog.Logger, query string, checkInterval time.Duration) *PeerManager {
	return &PeerManager{
		clock:         clockwork.NewRealClock(),
		log:           log,
		query:         query,
		checkInterval: checkInterval,
		peers:         mapset.NewSet[string](),
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
			peers := mapset.NewSet[string]()
			_, records, err := net.DefaultResolver.LookupSRV(ctx, "", "", pm.query)
			if err != nil {
				pm.log.Error("error resolving peers", "error", err)
				continue
			}
			for _, srv := range records {
				peerAddr := fmt.Sprintf("%s:%d", srv.Target, srv.Port)
				peers.Add(peerAddr)
			}

			added := peers.Difference(pm.peers)
			removed := pm.peers.Difference(peers)

			if added.Cardinality() != 0 || removed.Cardinality() != 0 {
				pm.peersMu.Lock()
				pm.log.Debug("updating peers list", "added", added.ToSlice(), "removed", removed.ToSlice(), "peers", peers.ToSlice())
				pm.checkCallback(removed.ToSlice(), added.ToSlice())
				pm.peers = peers
				pm.peersMu.Unlock()
			}
		}
	}
}

func (pm *PeerManager) Peers() []string {
	pm.peersMu.Lock()
	defer pm.peersMu.Unlock()
	return pm.peers.ToSlice()
}
