package capture

import (
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

type PacketHandler interface {
	HandlePacket(gopacket.Packet) error
	Flush() error
}

type PacketHandlerFunc func(gopacket.Packet) error

func (f PacketHandlerFunc) HandlePacket(p gopacket.Packet) error {
	return f(p)
}

func (f PacketHandlerFunc) Flush() error {
	return nil
}

var PacketPrinterHandler = PacketHandlerFunc(func(p gopacket.Packet) error {
	fmt.Println(p)
	return nil
})

type ChainPacketHandler struct {
	handlers []PacketHandler
}

func (chain *ChainPacketHandler) HandlePacket(p gopacket.Packet) error {
	for _, handler := range chain.handlers {
		err := handler.HandlePacket(p)
		if err != nil {
			return err
		}
	}
	return nil
}

func (chain *ChainPacketHandler) Flush() error {
	var err error
	for _, handler := range chain.handlers {
		err = errors.Join(err, handler.Flush())
	}
	return err
}

func ChainPacketHandlers(handlers ...PacketHandler) PacketHandler {
	return &ChainPacketHandler{handlers: handlers}
}
