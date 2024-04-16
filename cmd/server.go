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

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
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
		return runServer(listen)
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().String("listen-address", "127.0.0.1:48999", "Server listen address")
}

func runServer(listen string) error {
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	logger := slog.Default()
	slog.SetLogLoggerLevel(slog.LevelDebug)

	s := newGRPCServer(logger, &server{
		clock:   clockwork.NewRealClock(),
		log:     logger,
		promisc: true,
	})

	slog.Info("starting server", "listen-address", listen)
	if err := s.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}

type server struct {
	capperpb.UnimplementedCapperServer
	clock   clockwork.Clock
	log     *slog.Logger
	promisc bool
}

func (s *server) Capture(ctx context.Context, req *capperpb.CaptureRequest) (*capperpb.CaptureResponse, error) {
	var buf bytes.Buffer
	writeHandler := capture.NewPacketWriterHandler(&buf, uint32(req.GetSnaplen()), layers.LinkTypeEthernet)
	pcap := capture.New(s.log, writeHandler)
	err := pcap.Run(ctx, req.GetInterface(), req.GetFilter(), int(req.GetSnaplen()), s.promisc, req.GetNumPackets(), req.GetDuration().AsDuration())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error occurred while capturing packets: %s", err)
	}
	return &capperpb.CaptureResponse{Pcap: buf.Bytes()}, nil
}
func (s *server) StreamCapture(req *capperpb.CaptureRequest, stream capperpb.Capper_StreamCaptureServer) error {
	streamHandler := newStreamPacketHandler(uint32(req.GetSnaplen()), layers.LinkTypeEthernet, stream)
	pcap := capture.New(s.log, streamHandler)
	err := pcap.Run(stream.Context(), req.GetInterface(), req.GetFilter(), int(req.GetSnaplen()), s.promisc, req.GetNumPackets(), req.GetDuration().AsDuration())
	if err != nil {
		return status.Errorf(codes.Internal, "error occurred while capturing packets: %s", err)
	}
	return nil
}

// newStreamPacketHandler returns a PacketHandler which writes the packets as
// bytes to the given Capper_StreamCaptureServer stream.
func newStreamPacketHandler(snaplen uint32, linkType layers.LinkType, stream capperpb.Capper_StreamCaptureServer) capture.PacketHandler {
	var buf bytes.Buffer
	writeHandler := capture.NewPacketWriterHandler(&buf, snaplen, linkType)
	streamHandler := capture.PacketHandlerFunc(func(p gopacket.Packet) error {
		// send the packet on the stream
		if err := stream.Send(&capperpb.StreamCaptureResponse{
			Data: buf.Bytes(),
		}); err != nil {
			return status.Errorf(codes.Internal, "error sending packet: %s", err)
		}
		// Reset the buffer after sending the contents
		buf.Reset()
		return nil
	})
	return capture.ChainPacketHandlers(writeHandler, streamHandler)
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
