package packet

import (
	"net/netip"
	"time"
)

// Direction of a captured packet relative to the interface it was seen on.
type Direction uint8

const (
	Ingress Direction = 0
	Egress  Direction = 1
)

func (d Direction) String() string {
	if d == Egress {
		return "egress"
	}
	return "ingress"
}

// LinkType mirrors the libpcap DLT/LINKTYPE values we understand.
type LinkType uint32

const (
	LinkEthernet  LinkType = 1   // LINKTYPE_ETHERNET
	LinkRaw       LinkType = 101 // LINKTYPE_RAW
	LinkLinuxSLL  LinkType = 113 // LINKTYPE_LINUX_SLL
	LinkLinuxSLL2 LinkType = 276 // LINKTYPE_LINUX_SLL2
)

// Packet is a single captured frame.
type Packet struct {
	ID        uint64    `json:"id"`
	Time      time.Time `json:"time"`
	IfIndex   uint32    `json:"ifIndex"`
	IfName    string    `json:"ifName"`
	Direction Direction `json:"direction"`
	WireLen   uint32    `json:"wireLen"`
	CapLen    uint32    `json:"capLen"`
	Truncated bool      `json:"truncated"`
	LinkType  LinkType  `json:"linkType"`
	Data      []byte    `json:"-"`
	Summary   Summary   `json:"summary"`
	Meta      Meta      `json:"-"`
}

// Summary holds the values shown in the packet list.
type Summary struct {
	Protocol string   `json:"protocol"`
	Layers   []string `json:"layers"`
	Src      string   `json:"src"`
	Dst      string   `json:"dst"`
	SrcIP    string   `json:"srcIp,omitempty"`
	DstIP    string   `json:"dstIp,omitempty"`
	SrcPort  uint16   `json:"srcPort,omitempty"`
	DstPort  uint16   `json:"dstPort,omitempty"`
	Info     string   `json:"info"`
}

// Meta is the denormalised view of a packet used by the display filter engine
// and by the conversation tracker. It is never serialised to clients.
type Meta struct {
	ID     uint64
	Number uint64

	FrameLen int
	CapLen   int

	LinkType LinkType
	Layers   []string

	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16

	EthSrc  string
	EthDst  string
	EthType uint16
	VLAN    int

	IPVersion int
	IPProto   uint8
	TTL       uint8
	IPLen     int

	TCPFlags  uint8
	TCPSeq    uint32
	TCPAck    uint32
	TCPWin    uint16
	TCPPayLen int

	UDPLen int

	ICMPType uint8
	ICMPCode uint8

	ARPOp    uint16
	ARPSrcIP netip.Addr
	ARPDstIP netip.Addr

	DNSName     string
	DNSID       uint16
	DNSResponse bool

	HTTPMethod string
	HTTPURI    string
	HTTPHost   string
	HTTPCode   int

	TLSHandshake uint8
	TLSSNI       string

	App        string
	Payload    []byte
	TCPPayload []byte
	Raw        []byte
}

// HasLayer reports whether the given protocol layer was dissected.
func (m *Meta) HasLayer(name string) bool {
	for _, l := range m.Layers {
		if l == name {
			return true
		}
	}
	return false
}
