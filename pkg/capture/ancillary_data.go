package capture

import (
	"fmt"

	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
)

func GetCapperAncillaryData(ci gopacket.CaptureInfo) (*capperpb.AncillaryPacketData, error) {
	pancillaryData := ci.AncillaryData
	if len(pancillaryData) == 0 {
		return nil, fmt.Errorf("no gopacket AncillaryData")
	}
	var ancillaryData *capperpb.AncillaryPacketData
	for _, ad := range pancillaryData {
		var ok bool
		ancillaryData, ok = ad.(*capperpb.AncillaryPacketData)
		if ok {
			break
		}
	}
	if ancillaryData == nil {
		return nil, fmt.Errorf("no capper AncillaryPacketData found in gopacket AncillaryData")
	}
	return ancillaryData, nil
}
