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
	"github.com/gopacket/gopacket/pcapgo"
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
		clock: clockwork.NewRealClock(),
		log:   logger,
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
	clock clockwork.Clock
	log   *slog.Logger
}

func (s *server) Capture(ctx context.Context, req *capperpb.CaptureRequest) (*capperpb.CaptureResponse, error) {
	captureDuration := req.GetDuration().AsDuration()
	s.log.Debug("starting capture", "num_packets", req.GetNumPackets(), "duration", captureDuration)

	device := "any"
	snaplen := 262144
	promisc := true
	handle, err := newHandle(ctx, device, req.GetFilter(), snaplen, promisc)
	if err != nil {
		return nil, fmt.Errorf("error creating handle: %w", err)
	}
	defer handle.Close()

	var buf bytes.Buffer
	pcapw := pcapgo.NewWriter(&buf)
	if err := pcapw.WriteFileHeader(uint32(handle.SnapLen()), handle.LinkType()); err != nil {
		return nil, fmt.Errorf("error writing file header: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	count := uint64(0)
	start := s.clock.Now()
	for packet := range packetSource.PacketsCtx(ctx) {
		if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			return nil, fmt.Errorf("error writing packet: %w", err)
		}
		count++
		if req.GetNumPackets() != 0 && count > req.GetNumPackets() {
			s.log.Debug("reached num_packets limit, stopping capture", "num_packets", req.GetNumPackets())
			break
		}

		if captureDuration != 0 && s.clock.Since(start) > captureDuration {
			s.log.Debug("hit duration limit, stopping capture", "duration", captureDuration)
			break
		}
	}
	return &capperpb.CaptureResponse{Pcap: buf.Bytes()}, err
}

func (s *server) StreamCapture(req *capperpb.CaptureRequest, stream capperpb.Capper_StreamCaptureServer) error {
	captureDuration := req.GetDuration().AsDuration()
	s.log.Debug("starting capture", "num_packets", req.GetNumPackets(), "duration", captureDuration)
	ctx := stream.Context()

	device := "any"
	snaplen := 262144
	promisc := true
	handle, err := newHandle(ctx, device, req.GetFilter(), snaplen, promisc)
	if err != nil {
		return fmt.Errorf("error creating handle: %w", err)
	}
	defer handle.Close()

	var buf bytes.Buffer
	pcapw := pcapgo.NewWriter(&buf)
	if err := pcapw.WriteFileHeader(uint32(handle.SnapLen()), handle.LinkType()); err != nil {
		return fmt.Errorf("error writing file header: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	count := uint64(0)
	start := s.clock.Now()
	for packet := range packetSource.PacketsCtx(ctx) {
		if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			return fmt.Errorf("error writing packet: %w", err)
		}
		err := stream.Send(&capperpb.StreamCaptureResponse{
			Data: buf.Bytes(),
		})
		if err != nil {
			return fmt.Errorf("error sending response: %w", err)
		}
		count++
		buf.Reset() // reset the buffer after sending
		if req.GetNumPackets() != 0 && count > req.GetNumPackets() {
			s.log.Debug("reached num_packets limit, stopping capture", "num_packets", req.GetNumPackets())
			break
		}

		if captureDuration != 0 && s.clock.Since(start) > captureDuration {
			s.log.Debug("hit duration limit, stopping capture", "duration", captureDuration)
			break
		}
	}
	return nil
}
