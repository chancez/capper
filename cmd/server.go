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
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
	serverCmd.Flags().String("listen-address", "127.0.0.1:8080", "Server listen address")
}

func runServer(listen string) error {
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s := grpc.NewServer()

	logger := slog.Default()
	slog.SetLogLoggerLevel(slog.LevelDebug)

	srv := &server{
		clock:   clockwork.NewRealClock(),
		log:     logger,
		promisc: true,
	}
	capperpb.RegisterCapperServer(s, srv)
	reflection.Register(s)
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
	iface := req.GetInterface()
	if iface == "" {
		iface = "any"
	}
	var buf bytes.Buffer
	wh := capture.NewPacketWriterHandler(&buf, uint32(req.GetSnaplen()), layers.LinkTypeEthernet)
	pcap := capture.New(s.log, wh)
	err := pcap.Run(ctx, iface, req.GetFilter(), int(req.GetSnaplen()), s.promisc, req.GetNumPackets(), req.GetDuration().AsDuration())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error occurred while capturing packets: %s", err)
	}
	return &capperpb.CaptureResponse{Pcap: buf.Bytes()}, nil
}

func (s *server) StreamCapture(req *capperpb.CaptureRequest, stream capperpb.Capper_StreamCaptureServer) error {
	iface := req.GetInterface()
	if iface == "" {
		iface = "any"
	}
	h := newStreamPacketHandler(uint32(req.GetSnaplen()), layers.LinkTypeEthernet, stream)
	pcap := capture.New(s.log, h)
	err := pcap.Run(stream.Context(), iface, req.GetFilter(), int(req.GetSnaplen()), s.promisc, req.GetNumPackets(), req.GetDuration().AsDuration())
	if err != nil {
		return status.Errorf(codes.Internal, "error occurred while capturing packets: %s", err)
	}
	return nil
}

// newStreamPacketHandler returns a PacketHandler which writes the packets as
// bytes to the given Capper_StreamCaptureServer stream.
func newStreamPacketHandler(snaplen uint32, linkType layers.LinkType, stream capperpb.Capper_StreamCaptureServer) capture.PacketHandler {
	var buf bytes.Buffer
	wh := capture.NewPacketWriterHandler(&buf, snaplen, linkType)
	streamH := capture.PacketHandlerFunc(func(p gopacket.Packet) error {
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
	return capture.ChainPacketHandlers(wh, streamH)
}
