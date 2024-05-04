package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/hashicorp/serf/serf"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
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
		logLevel, err := cmd.Flags().GetString("log-level")
		if err != nil {
			return err
		}
		serfOpts, err := getSerfOpts(cmd.Flags())
		if err != nil {
			return err
		}
		peerServerPort, err := cmd.Flags().GetString("peer-server-port")
		if err != nil {
			return err
		}

		log, err := newLevelLogger(logLevel)
		if err != nil {
			return err
		}
		return runGateway(cmd.Context(), log, listen, serfOpts, peerServerPort)
	},
}

func init() {
	rootCmd.AddCommand(gatewayCmd)
	gatewayCmd.Flags().String("listen-address", "127.0.0.1:48999", "Gateway listen address")
	gatewayCmd.Flags().String("log-level", "info", "Configure the log level.")
	gatewayCmd.Flags().AddFlagSet(newSerfFlags())
	gatewayCmd.Flags().String("peer-server-port", "48999", "Port to connect to peers on for queries.")
}

func runGateway(ctx context.Context, logger *slog.Logger, listen string, serfOpts serfOpts, peerServerPort string) error {
	logger = logger.With("component", "gateway")

	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	logger.Info("starting serf", "listen", serfOpts.ListenAddr, "node-name", serfOpts.NodeName, "peers", serfOpts.Peers)
	serf, err := newSerf(serfOpts.ListenAddr, serfOpts.NodeName, serfOpts.Peers, "gateway")
	if err != nil {
		return fmt.Errorf("error creating serf cluster: %w", err)
	}
	defer serf.Leave()

	clientPool := NewPeerClientConnPool(logger.With("subsystem", "client-pool"), 5*time.Second)

	gatewaySrv := newGRPCServer(logger, &gateway{
		clock:          clockwork.NewRealClock(),
		log:            logger,
		clientPool:     clientPool,
		serf:           serf,
		peerServerPort: peerServerPort,
	})

	eg, ctx := errgroup.WithContext(ctx)
	logger.Info("starting gateway", "listen-address", listen)
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
	clock          clockwork.Clock
	log            *slog.Logger
	clientPool     *PeerClientConnPool
	serf           *serf.Serf
	peerServerPort string
}

func (s *gateway) Capture(req *capperpb.CaptureRequest, stream capperpb.Capper_CaptureServer) error {
	peers := s.getPeers()
	if len(peers) == 0 {
		s.log.Error("no peers")
		return status.Error(codes.Internal, "no peers")
	}
	s.log.Debug("found peers", "peers", peers)

	if nodeName := req.GetNodeName(); nodeName != "" {
		for _, peer := range peers {
			if peer.Name == nodeName {
				if peer.Status != serf.StatusAlive {
					s.log.Warn("skipping peer, status is not alive", "status", peer.Status)
					return status.Errorf(codes.Unavailable, "node %s status is %s", nodeName, peer.Status)
				}
				return s.captureNode(stream.Context(), peer, req, stream)
			}
		}
		return status.Errorf(codes.InvalidArgument, "unable to find peer for node %s", nodeName)
	}

	return s.captureMultiNodes(peers, req, stream)

}

func (s *gateway) captureNode(ctx context.Context, peer serf.Member, req *capperpb.CaptureRequest, stream capperpb.Capper_CaptureServer) error {
	conn, err := s.getClient(ctx, peer)
	if err != nil {
		return err
	}

	c := capperpb.NewCapperClient(conn)
	s.log.Debug("starting peer stream", "peer", peer.Name)
	peerStream, err := c.Capture(ctx, req)
	if err != nil {
		return fmt.Errorf("error creating stream: %w", err)
	}

	// Begins reading from the stream
	s.log.Debug("started reading from peer stream", "peer", peer.Name)
	defer func() {
		s.log.Debug("finished reading from peer stream", "peer", peer.Name)
	}()
	for {
		resp, err := peerStream.Recv()
		if err == io.EOF {
			return nil
		}
		if status.Code(err) == codes.Canceled {
			return nil
		}
		if err != nil {
			return fmt.Errorf("error receiving from peer stream: %w", err)
		}
		err = stream.Send(resp)
		if status.Code(err) == codes.Canceled {
			return nil
		}
		if err != nil {
			return fmt.Errorf("error sending data to client stream: %w", err)
		}
	}
}

func (s *gateway) captureMultiNodes(peers []serf.Member, req *capperpb.CaptureRequest, stream capperpb.Capper_CaptureServer) error {
	eg, ctx := errgroup.WithContext(stream.Context())
	for _, peer := range peers {
		peer := peer
		if peer.Status != serf.StatusAlive {
			s.log.Warn("skipping peer, status is not alive", "status", peer.Status)
			continue
		}
		eg.Go(func() error {
			return s.captureNode(ctx, peer, req, stream)
		})
	}
	err := eg.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	if err != nil {
		return err
	}
	return nil
}

func (s *gateway) getPeers() []serf.Member {
	var peers []serf.Member
	for _, member := range s.serf.Members() {
		// Only connect to capper servers
		if role, ok := member.Tags["role"]; !ok || role != "server" {
			continue
		}
		peers = append(peers, member)
	}
	return peers
}

func (s *gateway) getPeerAddress(member serf.Member) string {
	return net.JoinHostPort(member.Addr.String(), s.peerServerPort)
}

func (s *gateway) getClient(ctx context.Context, peer serf.Member) (*grpc.ClientConn, error) {
	return s.clientPool.Client(ctx, s.getPeerAddress(peer))
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
