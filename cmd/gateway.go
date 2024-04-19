package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
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
		peers, err := cmd.Flags().GetStringSlice("peers")
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
		return runGateway(log, listen, peers)
	},
}

func init() {
	rootCmd.AddCommand(gatewayCmd)
	gatewayCmd.Flags().String("listen-address", "127.0.0.1:48999", "Gateway listen address")
	gatewayCmd.Flags().StringSlice("peers", []string{}, "List of peers")
	gatewayCmd.Flags().String("log-level", "info", "Configure the log level.")
}

func runGateway(logger *slog.Logger, listen string, peers []string) error {
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	logger = logger.With("component", "gateway")

	s := newGRPCServer(logger, &gateway{
		clock:       clockwork.NewRealClock(),
		log:         logger,
		peers:       peers,
		connTimeout: 5 * time.Second,
	})

	logger.Info("starting gateway", "listen-address", listen, "peers", peers)
	if err := s.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}

type gateway struct {
	capperpb.UnimplementedCapperServer
	clock       clockwork.Clock
	log         *slog.Logger
	peers       []string
	connTimeout time.Duration
}

func (s *gateway) StreamCapture(req *capperpb.CaptureRequest, stream capperpb.Capper_StreamCaptureServer) error {
	ctx := stream.Context()

	var peers []string
	for _, p := range s.peers {
		if strings.HasPrefix(p, "dnssrv+") {
			query := strings.TrimPrefix(p, "dnssrv+")
			_, records, err := net.DefaultResolver.LookupSRV(ctx, "", "", query)
			if err != nil {
				return status.Errorf(codes.Internal, "error resolving peers: %s", err)
			}
			for _, srv := range records {
				p = fmt.Sprintf("%s:%d", srv.Target, srv.Port)
			}
		}
		peers = append(peers, p)
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
		peerStream, err := c.StreamCapture(ctx, req)
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
			linkType = reader.LinkType()
			s.log.Debug("using first streams linkType", "link_type", linkType)
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
	handler := newStreamPacketHandler(uint32(req.GetSnaplen()), stream)

	s.log.Debug("receiving packets from clients")
	for packet := range merger.PacketsCtx(ctx) {
		// TODO: stream handler does not use link type and we have multiple link
		// types due to multiple handles being merged
		if err := handler.HandlePacket(linkType, packet); err != nil {
			return err
		}
	}
	return nil
}
