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

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/hashicorp/serf/serf"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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

	eventCh := make(chan serf.Event)
	serf, err := newSerf(serfOpts.ListenAddr, serfOpts.NodeName, serfOpts.Peers, "gateway", eventCh)
	if err != nil {
		return fmt.Errorf("error creating serf cluster: %w", err)
	}
	defer serf.Leave()

	clientPool := NewPeerClientConnPool(logger.With("subsystem", "client-pool"), 5*time.Second)

	gw := &gateway{
		clock:          clockwork.NewRealClock(),
		log:            logger,
		clientPool:     clientPool,
		serf:           serf,
		peerServerPort: peerServerPort,
		peerPods:       make(map[string]map[string]*capperpb.Pod),
	}
	srv := newGRPCServer(logger)

	capperpb.RegisterQuerierServer(srv, gw)
	healthpb.RegisterHealthServer(srv, health.NewServer())
	reflection.Register(srv)

	eg, ctx := errgroup.WithContext(ctx)
	logger.Info("starting gateway", "listen-address", listen)
	eg.Go(func() error {
		if err := srv.Serve(lis); err != nil {
			return fmt.Errorf("failed to serve: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		return gw.runPeerMetadataUpdater(ctx, logger, eventCh)
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
	capperpb.UnimplementedQuerierServer
	clock          clockwork.Clock
	log            *slog.Logger
	clientPool     *PeerClientConnPool
	serf           *serf.Serf
	peerServerPort string
	peerPodsMu     sync.Mutex
	peerPods       map[string]map[string]*capperpb.Pod
}

func (g *gateway) runPeerMetadataUpdater(ctx context.Context, logger *slog.Logger, eventCh chan serf.Event) error {
	t := time.NewTicker(nodeMetadataUpdateInterval)
	defer t.Stop()

	var wg sync.WaitGroup
	defer wg.Wait()

	reconcilePeers := func() error {
		for _, peer := range g.getPeers() {
			peer := peer
			g.peerPodsMu.Lock()
			_, ok := g.peerPods[peer.Name]
			g.peerPodsMu.Unlock()
			// If the peer already exists in our map, then there's already a
			// subscriber goroutine running and we don't need to continue processing this peer
			if ok {
				continue
			}

			// Start a new subscriber goroutine
			wg.Add(1)
			go func() {
				g.peerPodsMu.Lock()
				// Create a new map entry for this peers list of pods
				g.peerPods[peer.Name] = make(map[string]*capperpb.Pod)
				g.peerPodsMu.Unlock()

				defer func() {
					g.peerPodsMu.Lock()
					delete(g.peerPods, peer.Name)
					g.peerPodsMu.Unlock()
					g.log.Debug("peer NodeUpdate stream has stopped", "peer", peer.Name)
				}()

				conn, err := g.getClient(ctx, peer)
				if err != nil {
					return
				}
				c := capperpb.NewCapperClient(conn)
				g.log.Debug("starting peer NodeUpdate stream", "peer", peer.Name)

				nodeMetadataStream, err := c.NodeMetadata(ctx, &capperpb.NodeMetadataRequest{})
				if err != nil {
					return
				}

				for {
					resp, err := nodeMetadataStream.Recv()
					if err == io.EOF {
						return
					}
					if status.Code(err) == codes.Canceled || status.Code(err) == codes.Unavailable {
						// TOOD: retry unavailable: https://github.com/grpc/grpc-go/blob/master/examples/features/retry/client/main.go#L36
						return
					}
					if err != nil {
						g.log.Error("error receiving from peer metadata stream", "error", err)
						return
					}
					g.updatePeerMetadata(peer, resp.GetUpdates())
				}
			}()
		}
		return nil
	}

	// Reconcile once before we loop since we may have already missed some events
	// and the ticker may not trigger for a bit.
	if err := reconcilePeers(); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			logger.Info("got signal, stopping subscriber to node metadata updates")
			// TODO: Should we  wait for all the subscribers goroutines to stop?
			return ctx.Err()
		case <-eventCh:
			// Got a serf event, reconcile
			if err := reconcilePeers(); err != nil {
				return err
			}
		case <-t.C:
			// Periodically re-list peers in case we missed an event for some reason
			if err := reconcilePeers(); err != nil {
				return err
			}
		}
	}
}

func (g *gateway) pods(peer serf.Member, namespace string) []*capperpb.Pod {
	g.peerPodsMu.Lock()
	defer g.peerPodsMu.Unlock()
	peerPodsMap := g.peerPods[peer.Name]
	var pods []*capperpb.Pod
	for _, pod := range peerPodsMap {
		if namespace != "" && pod.GetNamespace() != namespace {
			continue
		}
		pods = append(pods, pod)
	}
	return pods
}

func (g *gateway) podExists(peer serf.Member, pod *capperpb.Pod) bool {
	g.peerPodsMu.Lock()
	defer g.peerPodsMu.Unlock()
	peerPodsMap := g.peerPods[peer.Name]
	key := podMapKey(pod)
	_, ok := peerPodsMap[key]
	return ok
}

func (g *gateway) updatePeerMetadata(peer serf.Member, update *capperpb.NodeMetadataUpdate) {
	g.peerPodsMu.Lock()
	defer g.peerPodsMu.Unlock()
	peerPodsMap := g.peerPods[peer.Name]

	var added, removed []string
	for _, pod := range update.GetPodUpdates().GetRemovedPods() {
		key := podMapKey(pod)
		removed = append(removed, key)
		delete(peerPodsMap, key)
	}
	for _, pod := range update.GetPodUpdates().GetAddedPods() {
		key := podMapKey(pod)
		added = append(added, key)
		peerPodsMap[key] = pod
	}
	if len(added) == 0 && len(removed) == 0 {
		g.log.Debug("no changes to peer pods in update", "peer", peer.Name)
		return
	}
	g.log.Debug("updated remote peer metadata", "peer", peer.Name, "added", added, "removed", removed)
}

func (g *gateway) CaptureQuery(req *capperpb.CaptureQueryRequest, stream capperpb.Querier_CaptureQueryServer) error {
	ctx := stream.Context()
	peers := g.getPeers()
	var nodes []serf.Member
	var targetPods []*capperpb.Pod
	var targetPodNamespaces []string
	for _, target := range req.GetTargets() {
		switch targetVal := target.GetTarget().(type) {
		case *capperpb.CaptureQueryTarget_Node:
			nodeName := targetVal.Node
			for _, peer := range peers {
				if peer.Name == nodeName {
					if peer.Status != serf.StatusAlive {
						g.log.Warn("skipping peer, status is not alive", "status", peer.Status)
						return status.Errorf(codes.Unavailable, "node %s status is %s", nodeName, peer.Status)
					}
					nodes = append(nodes, peer)
				}
			}
		case *capperpb.CaptureQueryTarget_Pod:
			targetPods = append(targetPods, target.GetPod())
		case *capperpb.CaptureQueryTarget_PodNamespace:
			targetPodNamespaces = append(targetPodNamespaces, target.GetPodNamespace())
		}
	}

	// If no nodes, pods, or pod namespaces were specified then default to all of the nodes
	if len(nodes) == 0 && len(targetPods) == 0 && len(targetPodNamespaces) == 0 {
		nodes = peers
	}

	eg, ctx := errgroup.WithContext(ctx)

	stop := make(chan struct{})
	forward := make(chan capture.TimestampedPacket)

	g.log.Debug("starting packet merger")
	heapDrainThreshold := 10
	flushInterval := time.Second
	mergeBufferSize := 100
	merger := capture.NewPacketMerger(
		g.log,
		[]capture.NamedPacketSource{{Name: "", PacketSource: capture.PacketSourceChan(forward)}},
		heapDrainThreshold, flushInterval, mergeBufferSize, 0,
	)

	eg.Go(func() error {
		defer close(stop)
		for packet := range merger.PacketsCtx(ctx) {
			err := stream.Send(&capperpb.CaptureResponse{
				Packet: packet.(*capture.CapperPacketWrapper).Packet,
			})
			if status.Code(err) == codes.Canceled {
				return nil
			}
			if err != nil {
				return fmt.Errorf("error sending data to client capture stream: %w", err)
			}
		}
		return nil
	})

	// Make a request for each node to be queried
	for _, node := range nodes {
		peer := node
		eg.Go(func() error {
			return g.captureNode(ctx, peer, req.GetCaptureRequest(), forward, stop, queryTarget{
				kind:     "node",
				nodeName: peer.Name,
			})
		})
	}

	// For each namespace, get the list of pods in that namespace for every peer,
	// and make a capture request for each
	for _, podNamespace := range targetPodNamespaces {
		podNamespace := podNamespace
		for _, peer := range peers {
			peer := peer
			peerPods := g.pods(peer, podNamespace)
			for _, pod := range peerPods {
				pod := pod
				eg.Go(func() error {
					captureReq := proto.Clone(req.GetCaptureRequest()).(*capperpb.CaptureRequest)
					// Override the pod filter to target the pod listed
					captureReq.K8SPodFilter = pod
					err := g.captureNode(ctx, peer, captureReq, forward, stop, queryTarget{
						kind: "pod",
						pod:  pod,
					})
					// The pod may no longer be running when we make the query
					if status.Code(err) == codes.NotFound {
						g.log.Warn("pod is no longer running on peer", "peer", peer.Name, "pod", pod)
						return nil
					}
					if err != nil {
						return fmt.Errorf("error querying peer %s for pod: %s: %w", peer.Name, pod, err)
					}
					return nil
				})
			}
		}
	}

	// Create a capture request for each pod being targeted, attempting to only query the peer running that pod.
	for _, pod := range targetPods {
		for _, peer := range peers {
			pod := pod
			peer := peer
			if !g.podExists(peer, pod) {
				continue
			}
			eg.Go(func() error {
				captureReq := proto.Clone(req.GetCaptureRequest()).(*capperpb.CaptureRequest)
				// Override the pod filter to the one specified in the target
				captureReq.K8SPodFilter = pod
				err := g.captureNode(ctx, peer, captureReq, forward, stop, queryTarget{
					kind: "pod",
					pod:  pod,
				})
				// The pod may no longer be running when we make the query
				if status.Code(err) == codes.NotFound {
					g.log.Warn("pod is no longer running on peer", "peer", peer.Name, "pod", pod)
					return nil
				}
				if err != nil {
					return fmt.Errorf("error querying peer %s for pod: %s: %w", peer.Name, pod, err)
				}
				return nil
			})
		}
	}

	if err := eg.Wait(); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}

	return nil
}

type queryTarget struct {
	kind     string
	pod      *capperpb.Pod
	nodeName string
}

func (target queryTarget) Target() string {
	switch target.kind {
	case "pod":
		return target.pod.GetNamespace() + "/" + target.pod.GetName()
	case "node":
		return target.nodeName
	default:
		return ""
	}
}
func (s *gateway) captureNode(ctx context.Context, peer serf.Member, req *capperpb.CaptureRequest, forward chan capture.TimestampedPacket, stop chan struct{}, target queryTarget) error {
	conn, err := s.getClient(ctx, peer)
	if err != nil {
		return err
	}

	c := capperpb.NewCapperClient(conn)
	s.log.Debug("starting peer Capture stream", "peer", peer.Name, "target_kind", target.kind, "target", target.Target())
	peerStream, err := c.Capture(ctx, req)
	if err != nil {
		return fmt.Errorf("error creating capture stream: %w", err)
	}

	// Begins reading from the stream
	s.log.Debug("started reading from peer capture stream", "peer", peer.Name, "target_kind", target.kind, "target", target.Target())
	defer func() {
		s.log.Debug("finished reading from peer capture stream", "peer", peer.Name, "target_kind", target.kind, "target", target.Target())
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
			return fmt.Errorf("error receiving from peer capture stream: %w", err)
		}

		select {
		case forward <- &capture.CapperPacketWrapper{Packet: resp.Packet}:
		case <-stop:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
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
