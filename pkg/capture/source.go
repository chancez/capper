package capture

import (
	"context"
)

type PacketSource interface {
	PacketsCtx(ctx context.Context) chan TimestampedPacket
}

type PacketSourceChan chan TimestampedPacket

func (ps PacketSourceChan) PacketsCtx(ctx context.Context) chan TimestampedPacket {
	output := make(chan TimestampedPacket)
	go ps.run(ctx, output)
	return output
}

func (ps PacketSourceChan) run(ctx context.Context, output chan TimestampedPacket) {
	for {
		select {
		case tsPacket := <-ps:
			select {
			case output <- tsPacket:
			case <-ctx.Done():
				close(output)
				return
			}
		case <-ctx.Done():
			close(output)
			return
		}
	}
}
