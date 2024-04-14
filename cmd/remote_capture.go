package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

var remoteCaptureCmd = &cobra.Command{
	Use:   "remote-capture [filter]",
	Short: "Capture packets remotely",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRemoteCapture,
}

func init() {
	rootCmd.AddCommand(remoteCaptureCmd)
	remoteCaptureCmd.Flags().StringP("address", "a", "127.0.0.1:8080", "Remote capper server address to connect to")
	remoteCaptureCmd.Flags().StringP("output", "o", "", "Store output into the file specified.")
	remoteCaptureCmd.Flags().BoolP("print", "P", false, "Output the packet summary/details, even if writing raw packet data using the -o option.")
	remoteCaptureCmd.Flags().Uint64P("num-packets", "n", 0, "Number of packets to capture.")
	remoteCaptureCmd.Flags().DurationP("duration", "d", 0, "Duration to capture packets.")
	remoteCaptureCmd.Flags().Duration("request-timeout", 0, "Request timeout")
	remoteCaptureCmd.Flags().Duration("connection-timeout", 10*time.Second, "Connection timeout")
}

func runRemoteCapture(cmd *cobra.Command, args []string) error {
	var filter string
	if len(args) == 1 {
		filter = args[0]
	}
	addr, err := cmd.Flags().GetString("address")
	if err != nil {
		return err
	}
	outputFile, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	alwaysPrint, err := cmd.Flags().GetBool("print")
	if err != nil {
		return err
	}
	numPackets, err := cmd.Flags().GetUint64("num-packets")
	if err != nil {
		return err
	}
	captureDuration, err := cmd.Flags().GetDuration("duration")
	if err != nil {
		return err
	}
	reqTimeout, err := cmd.Flags().GetDuration("request-timeout")
	if err != nil {
		return err
	}
	connTimeout, err := cmd.Flags().GetDuration("connection-timeout")
	if err != nil {
		return err
	}
	return remoteCapture(cmd.Context(), addr, connTimeout, reqTimeout, filter, outputFile, alwaysPrint, numPackets, captureDuration)
}

func remoteCapture(ctx context.Context, addr string, connTimeout, reqTimeout time.Duration, filter string, outputFile string, alwaysPrint bool, numPackets uint64, captureDuration time.Duration) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	connCtx := ctx
	connCancel := func() {}
	if connTimeout != 0 {
		connCtx, connCancel = context.WithTimeout(ctx, connTimeout)
	}
	conn, err := grpc.DialContext(connCtx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	connCancel()
	if err != nil {
		return fmt.Errorf("error connecting to server: %w", err)
	}
	defer conn.Close()
	c := capper.NewCapperClient(conn)

	stream, err := c.StreamCapture(ctx, &capper.CaptureRequest{
		Filter:     filter,
		NumPackets: numPackets,
		Duration:   durationpb.New(captureDuration),
	})
	if err != nil {
		return fmt.Errorf("error creating stream: %w", err)
	}

	var handlers []packetHandler
	if alwaysPrint || outputFile == "" {
		handlers = append(handlers, packetPrinterHandler)
	}
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("error opening output: %w", err)
		}
		defer f.Close()
		writeHandler := newPacketWriterHandler(f)
		handlers = append(handlers, writeHandler)
	}
	handler := chainPacketHandlers(handlers...)

	r, w := io.Pipe()
	var eg errgroup.Group

	// Takes the incoming packet data and parses it back into a gopacket.Packet
	// Which our handlers use to either print or write them to disk.
	eg.Go(func() error {
		// We have to initialize this in the go routine since initializing the
		// reader causes it to start reading from the io.Reader, trying to parse
		// the pcap header.
		pcapReader, err := pcapgo.NewReader(r)
		if err != nil {
			return fmt.Errorf("error creating pcap reader: %w", err)
		}
		packetSource := gopacket.NewPacketSource(pcapReader, pcapReader.LinkType())
		for packet := range packetSource.PacketsCtx(ctx) {
			handler.HandlePacket(pcapReader, packet)
		}
		return nil
	})

	// Read packets from the gRPC stream and send them to the reader go routine started above.
	eg.Go(func() error {
		defer w.Close()
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if status.Code(err) == codes.Canceled {
				break
			}
			if err != nil {
				return fmt.Errorf("error reading from stream: %w", err)
			}
			_, err = w.Write(resp.GetData())
			if err != nil {
				return fmt.Errorf("error writing data to buffer: %w", err)
			}
		}
		return nil
	})

	err = eg.Wait()
	if err != nil {
		return err
	}

	return nil
}
