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

	"github.com/chancez/capper/pkg/capture"
	containerdutil "github.com/chancez/capper/pkg/containerd"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/containerd/containerd"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/hashicorp/serf/serf"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

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

	serf, err := newSerf(serfOpts.ListenAddr, serfOpts.NodeName, serfOpts.Peers, "server")
	if err != nil {
		return fmt.Errorf("error creating serf cluster: %w", err)
	}
	defer serf.Leave()

	s := newGRPCServer(logger, &server{
		clock:            clockwork.NewRealClock(),
		log:              logger,
		containerdClient: containerdClient,
		nodeName:         serfOpts.NodeName,
		serf:             serf,
	})

	go func() {
		<-ctx.Done()
		logger.Info("got signal, shutting down server")
		s.GracefulStop()
	}()

	logger.Info("starting server", "listen-address", listen)
	defer logger.Info("server has exited")
	if err := s.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}

type server struct {
	capperpb.UnimplementedCapperServer
	clock            clockwork.Clock
	log              *slog.Logger
	containerdClient *containerd.Client
	nodeName         string
	serf             *serf.Serf
}

func (s *server) getNetns(ctx context.Context, req *capperpb.CaptureRequest) (string, error) {
	k8sNs := req.GetK8SPodFilter().GetNamespace()
	k8sPod := req.GetK8SPodFilter().GetPod()
	if k8sNs != "" && k8sPod != "" {
		if s.containerdClient == nil {
			return "", status.Error(codes.InvalidArgument, "containerd not enabled, querying k8s pod is disabled")
		}
		s.log.Debug("looking up k8s pod in containerd", "pod", k8sPod, "namespace", k8sNs)
		podNetns, err := containerdutil.GetPodNetns(ctx, s.containerdClient, k8sPod, k8sNs)
		if err != nil {
			return "", status.Errorf(codes.Internal, "error getting pod namespace: %s", err)
		}
		if podNetns == "" {
			return "", status.Errorf(codes.NotFound, "could not find netns for pod '%s/%s'", k8sNs, k8sPod)
		}
		s.log.Debug("found netns for pod", "pod", k8sPod, "namespace", k8sNs, "netns", podNetns)
		return podNetns, nil
	}
	return "", nil
}

func (s *server) Capture(req *capperpb.CaptureRequest, stream capperpb.Capper_CaptureServer) error {
	ctx := stream.Context()
	netns, err := s.getNetns(ctx, req)
	if err != nil {
		return status.Errorf(codes.Internal, "error getting netns: %s", err)
	}

	conf := capture.Config{
		Filter:          req.GetFilter(),
		Snaplen:         int(req.GetSnaplen()),
		Promisc:         req.GetNoPromiscuousMode(),
		NumPackets:      req.GetNumPackets(),
		CaptureDuration: req.GetDuration().AsDuration(),
	}

	handle, err := capture.NewMulti(ctx, s.log, req.GetInterface(), netns, conf)
	if err != nil {
		return err
	}
	defer handle.Close()
	linkType := handle.LinkType()

	header := metadata.Pairs("link_type", strconv.Itoa(int(linkType)))
	err = grpc.SendHeader(ctx, header)
	if err != nil {
		return status.Errorf(codes.Internal, "error sending header: %s", err)
	}

	streamHandler, err := newStreamPacketHandler(linkType, uint32(req.GetSnaplen()), stream)
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
func newStreamPacketHandler(linkType layers.LinkType, snaplen uint32, stream capperpb.Capper_CaptureServer) (capture.PacketHandler, error) {
	var buf bytes.Buffer
	writeHandler, err := capture.NewPcapWriterHandler(&buf, linkType, snaplen)
	if err != nil {
		return nil, err
	}
	streamHandler := capture.PacketHandlerFunc(func(p gopacket.Packet) error {
		// send the packet on the stream
		if err := stream.Send(&capperpb.CaptureResponse{
			Data: buf.Bytes(),
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

func newGRPCServer(logger *slog.Logger, capperSrv capperpb.CapperServer) *grpc.Server {
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

	capperpb.RegisterCapperServer(s, capperSrv)
	healthpb.RegisterHealthServer(s, health.NewServer())
	reflection.Register(s)
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
