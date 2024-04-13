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

	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
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
		device:  "any",
		snaplen: 262144,
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
	device  string
	snaplen int
	promisc bool
}

func (s *server) Capture(ctx context.Context, req *capperpb.CaptureRequest) (*capperpb.CaptureResponse, error) {
	var buf bytes.Buffer
	wh := newPacketWriterHandler(&buf)
	pcap := newPacketCapture(s.log, wh)
	err := pcap.Run(ctx, s.device, req.GetFilter(), s.snaplen, s.promisc, req.GetNumPackets(), req.GetDuration().AsDuration())
	if err != nil {
		return nil, fmt.Errorf("error occurred while capturing packets: %w", err)
	}
	return &capperpb.CaptureResponse{Pcap: buf.Bytes()}, err
}

func (s *server) StreamCapture(req *capperpb.CaptureRequest, stream capperpb.Capper_StreamCaptureServer) error {
	ctx := stream.Context()
	var buf bytes.Buffer
	wh := newPacketWriterHandler(&buf)
	h := packetHandlerFunc(func(h *pcap.Handle, p gopacket.Packet) error {
		// Write the packet to the buffer
		if err := wh.HandlePacket(h, p); err != nil {
			return err
		}
		// send the packet on the stream
		if err := stream.Send(&capperpb.StreamCaptureResponse{
			Data: buf.Bytes(),
		}); err != nil {
			return fmt.Errorf("error sending packet: %w", err)
		}
		// Reset the buffer after sending the contents
		buf.Reset()
		return nil
	})
	pcap := newPacketCapture(s.log, h)
	err := pcap.Run(ctx, s.device, req.GetFilter(), s.snaplen, s.promisc, req.GetNumPackets(), req.GetDuration().AsDuration())
	if err != nil {
		return fmt.Errorf("error occurred while capturing packets: %w", err)
	}
	return err
}
