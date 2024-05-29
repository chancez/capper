/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/chancez/capper/pkg/capture"
	containerdutil "github.com/chancez/capper/pkg/containerd"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/hashicorp/serf/serf"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const nodeMetadataUpdateInterval = 5 * time.Second

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts a capture server",
	RunE: func(cmd *cobra.Command, args []string) error {
		listen, err := cmd.Flags().GetString("listen-address")
		if err != nil {
			return err
		}
		enableContainerd, err := cmd.Flags().GetBool("enable-containerd")
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

		log, err := newLevelLogger(logLevel)
		if err != nil {
			return err
		}

		return runServer(cmd.Context(), log, listen, serfOpts, enableContainerd)
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().String("listen-address", "127.0.0.1:48999", "Server listen address")
	serverCmd.Flags().Bool("enable-containerd", false, "Enable containerd/Kubernetes integration")
	serverCmd.Flags().String("log-level", "info", "Configure the log level.")
	serverCmd.Flags().AddFlagSet(newSerfFlags())
}

func runServer(ctx context.Context, logger *slog.Logger, listen string, serfOpts serfOpts, enableContainerd bool) error {
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	var containerdClient *containerd.Client
	if enableContainerd {
		containerdSock := "/run/containerd/containerd.sock"
		logger.Debug("connecting to containerd", "addr", containerdSock)
		var err error
		containerdClient, err = containerdutil.New(containerdSock)
		if err != nil {
			return fmt.Errorf("error connecting to containerd: %w", err)
		}
		defer containerdClient.Close()
	}

	logger.Info("starting serf", "listen", serfOpts.ListenAddr, "node-name", serfOpts.NodeName, "peers", serfOpts.Peers)
	serf, err := newSerf(serfOpts.ListenAddr, serfOpts.NodeName, serfOpts.Peers, "server")
	if err != nil {
		return fmt.Errorf("error creating serf cluster: %w", err)
	}
	defer serf.Leave()

	srv := newGRPCServer(logger)
	capperServer := &server{
		clock:            clockwork.NewRealClock(),
		log:              logger,
		containerdClient: containerdClient,
		serf:             serf,
		metadata: nodeMetadata{
			nodeName: serfOpts.NodeName,
			pods:     make(map[string]*capperpb.Pod),
		},
		metadataSubscribers: make(map[chan *capperpb.NodeMetadataUpdate]struct{}),
	}

	capperpb.RegisterCapperServer(srv, capperServer)
	healthpb.RegisterHealthServer(srv, health.NewServer())
	reflection.Register(srv)

	go func() {
		t := time.NewTicker(nodeMetadataUpdateInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				logger.Info("got signal, stopping node metadata updates")
				return
			case <-t.C:
				err := capperServer.updateNodeMetadata(ctx)
				if err != nil {
					logger.Error("error updating node metadata", "error", err)
				}
			}
		}
	}()

	go func() {
		<-ctx.Done()
		logger.Info("got signal, shutting down server")
		srv.GracefulStop()
	}()

	logger.Info("starting server", "listen-address", listen)
	defer logger.Info("server has exited")
	if err := srv.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}

type server struct {
	capperpb.UnimplementedCapperServer
	clock            clockwork.Clock
	log              *slog.Logger
	containerdClient *containerd.Client
	serf             *serf.Serf

	metadataMu          sync.Mutex
	metadata            nodeMetadata
	metadataSubscribers map[chan *capperpb.NodeMetadataUpdate]struct{}
}

type nodeMetadata struct {
	nodeName string
	pods     map[string]*capperpb.Pod
}

func (s *server) updateNodeMetadata(ctx context.Context) error {
	if s.containerdClient != nil {
		ctrCtx := namespaces.WithNamespace(ctx, "k8s.io")
		containers, err := s.containerdClient.Containers(ctrCtx)
		if err != nil {
			return err
		}
		newPods := make(map[string]*capperpb.Pod)
		for _, ctr := range containers {
			spec, err := ctr.Spec(ctrCtx)
			if err != nil {
				return err
			}
			pod := &capperpb.Pod{}
			// set the pod namespace/name
			for key, value := range spec.Annotations {
				switch key {
				case "io.kubernetes.cri.sandbox-name":
					pod.Name = value
				case "io.kubernetes.cri.sandbox-namespace":
					pod.Namespace = value
				}
			}
			if pod.GetNamespace() != "" && pod.GetName() != "" {
				newPods[pod.GetNamespace()+"/"+pod.GetName()] = pod
			}
		}

		// diff the new and the old
		added := make([]*capperpb.Pod, 0)
		for key, pod := range newPods {
			if _, ok := s.metadata.pods[key]; !ok {
				added = append(added, pod)
			}
		}

		removed := make([]*capperpb.Pod, 0)
		for key, pod := range s.metadata.pods {
			if _, ok := newPods[key]; !ok {
				removed = append(removed, pod)
			}
		}

		if len(added) == 0 && len(removed) == 0 {
			s.log.Debug("no updates for local pod metadata")
			return nil
		}

		s.metadataMu.Lock()
		defer s.metadataMu.Unlock()

		s.log.Debug("updating local pod metadata", "added", added, "removed", removed)
		defer s.log.Debug("finished updating local pod metadata")

		s.metadata.pods = newPods

		update := &capperpb.NodeMetadataUpdate{
			NodeName: s.metadata.nodeName,
			PodUpdates: &capperpb.PodMetadataUpdate{
				AddedPods: added, RemovedPods: removed,
			},
		}
		// send node metadata update delta to any listening subscribers
		var eg errgroup.Group
		for ch := range s.metadataSubscribers {
			ch := ch
			// Send each update in a separate Go routine since some subscribers might
			// be slow to process the update
			eg.Go(func() error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case ch <- update:
					return nil
				}
			})
		}
		if err := eg.Wait(); err != nil {
			return fmt.Errorf("error waiting for node metadata updates to be processed by remote subscribers: %w", err)
		}
	}

	return nil
}

func (s *server) getPodNetns(ctx context.Context, pod, namespace string) (string, error) {
	if s.containerdClient == nil {
		return "", status.Error(codes.InvalidArgument, "containerd not enabled, querying k8s pod is disabled")
	}
	s.log.Debug("looking up k8s pod in containerd", "pod", pod, "namespace", namespace)
	podNetns, err := containerdutil.GetPodNetns(ctx, s.containerdClient, pod, namespace)
	if err != nil {
		return "", status.Errorf(codes.Internal, "error getting pod namespace: %s", err)
	}
	if podNetns == "" {
		return "", status.Errorf(codes.NotFound, "could not find netns for pod '%s/%s'", namespace, pod)
	}
	s.log.Debug("found netns for pod", "pod", pod, "namespace", namespace, "netns", podNetns)
	return podNetns, nil
}

func (s *server) Capture(req *capperpb.CaptureRequest, stream capperpb.Capper_CaptureServer) error {
	ctx := stream.Context()
	pod := req.GetK8SPodFilter().GetPod()
	namespace := req.GetK8SPodFilter().GetNamespace()
	var netns string
	if pod != "" && namespace != "" {
		var err error
		netns, err = s.getPodNetns(ctx, pod, namespace)
		if err != nil {
			return status.Errorf(codes.Internal, "error getting netns: %s", err)
		}
	}

	conf := capture.Config{
		Filter:          req.GetFilter(),
		Snaplen:         int(req.GetSnaplen()),
		Promisc:         req.GetNoPromiscuousMode(),
		NumPackets:      req.GetNumPackets(),
		CaptureDuration: req.GetDuration().AsDuration(),
	}

	return s.capture(ctx, req.GetInterface(), netns, conf, stream)
}

func (s *server) NodeMetadata(req *capperpb.NodeMetadataRequest, stream capperpb.Capper_NodeMetadataServer) error {
	ctx := stream.Context()

	// Create a new channel for this subscriber and store it in the metadataSubscribers map
	s.metadataMu.Lock()
	initialPods := make([]*capperpb.Pod, 0, len(s.metadata.pods))
	for _, pod := range s.metadata.pods {
		initialPods = append(initialPods, pod)
	}
	updatesCh := make(chan *capperpb.NodeMetadataUpdate)
	s.metadataSubscribers[updatesCh] = struct{}{}
	s.metadataMu.Unlock()

	// Remove the updates channel from the map of subscribers when the RPC ends
	defer func() {
		s.metadataMu.Lock()
		delete(s.metadataSubscribers, updatesCh)
		s.metadataMu.Unlock()
	}()

	// Send the subscriber the list of initial pods this server has
	if err := stream.Send(&capperpb.NodeMetadataResponse{
		Updates: &capperpb.NodeMetadataUpdate{
			NodeName: s.metadata.nodeName,
			PodUpdates: &capperpb.PodMetadataUpdate{
				AddedPods: initialPods,
			},
		},
	}); err != nil {
		errCode := status.Code(err)
		if errCode == codes.Canceled || errCode == codes.Unavailable {
			return nil
		}
		return fmt.Errorf("error sending metadata update: %w", err)
	}

	// Wait for updates to the node metadata or for the stream to be cancelled.
	for {
		select {
		case update := <-updatesCh:
			if err := stream.Send(&capperpb.NodeMetadataResponse{
				Updates: update,
			}); err != nil {
				errCode := status.Code(err)
				if errCode == codes.Canceled || errCode == codes.Unavailable {
					return nil
				}
				return fmt.Errorf("error sending metadata update: %w", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *server) capture(ctx context.Context, ifaces []string, netns string, conf capture.Config, stream capperpb.Capper_CaptureServer) error {
	handle, err := capture.NewMulti(ctx, s.log, ifaces, netns, conf)
	if err != nil {
		return err
	}
	defer handle.Close()
	linkType := handle.LinkType()

	streamHandler, err := newStreamPacketHandler(linkType, uint32(conf.Snaplen), netns, ifaces, stream)
	if err != nil {
		return status.Errorf(codes.Internal, "error occurred while capturing packets: %s", err)
	}
	err = handle.Start(ctx, streamHandler)
	if err != nil {
		return status.Errorf(codes.Internal, "error occurred while capturing packets: %s", err)
	}
	return nil
}

// newStreamPacketHandler returns a PacketHandler which writes the packets as
// bytes to the given Capper_CaptureServer stream.
func newStreamPacketHandler(linkType layers.LinkType, snaplen uint32, netns string, ifaces []string, stream capperpb.Capper_CaptureServer) (capture.PacketHandler, error) {
	var buf bytes.Buffer
	writeHandler, err := capture.NewPcapWriterHandler(&buf, linkType, snaplen)
	if err != nil {
		return nil, err
	}
	streamHandler := capture.PacketHandlerFunc(func(p gopacket.Packet) error {
		// send the packet on the stream
		if err := stream.Send(&capperpb.CaptureResponse{
			Data:      buf.Bytes(),
			LinkType:  int64(linkType),
			Netns:     netns,
			Interface: ifaces,
		}); err != nil {
			errCode := status.Code(err)
			if errCode == codes.Canceled || errCode == codes.Unavailable {
				return nil
			}
			return fmt.Errorf("error sending packet: %w", err)
		}
		// Reset the buffer after sending the contents
		buf.Reset()
		return nil
	})
	return capture.ChainPacketHandlers(writeHandler, streamHandler), nil
}

func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

func newGRPCServer(logger *slog.Logger) *grpc.Server {
	opts := []logging.Option{
		logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
		logging.WithCodes(logging.DefaultErrorToCode),
		logging.WithLevels(logging.DefaultClientCodeToLevel),
		logging.WithDurationField(logging.DefaultDurationToFields),
	}

	s := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			logging.UnaryServerInterceptor(InterceptorLogger(logger), opts...),
		),
		grpc.ChainStreamInterceptor(
			logging.StreamServerInterceptor(InterceptorLogger(logger), opts...),
		),
	)

	return s
}

func newSerf(listen string, nodeName string, peers []string, role string) (*serf.Serf, error) {
	serfAddr, serfPortStr, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, fmt.Errorf("failed to parse serf addr: %w", err)
	}
	serfPort, err := strconv.Atoi(serfPortStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse serf addr: %w", err)
	}

	serfConf := serf.DefaultConfig()
	serfConf.NodeName = nodeName
	serfConf.MemberlistConfig.BindAddr = serfAddr
	serfConf.MemberlistConfig.BindPort = serfPort
	serfConf.MemberlistConfig.AdvertisePort = serfPort
	serfConf.Tags = map[string]string{
		"role": role,
	}
	serf, err := serf.Create(serfConf)
	if err != nil {
		return nil, fmt.Errorf("error creating serf cluster: %w", err)
	}

	_, err = serf.Join(peers, true)
	if err != nil {
		return nil, fmt.Errorf("error adding peers to serf: %w", err)
	}
	return serf, nil
}
