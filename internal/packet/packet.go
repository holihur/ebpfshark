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
	LinkIEEE80211 LinkType = 105 // LINKTYPE_IEEE802_11
	LinkRadiotap  LinkType = 127 // LINKTYPE_IEEE802_11_RADIOTAP
)

// LayerMask is a compact bitset of protocol layers present in a packet.
type LayerMask uint64

const (
	LayerEth LayerMask = 1 << iota
	LayerVLAN
	LayerARP
	LayerIPv4
	LayerIPv6
	LayerTCP
	LayerUDP
	LayerSCTP
	LayerICMP
	LayerICMPv6
	LayerIGMP
	LayerGRE
	LayerMPLS
	LayerVXLAN
	LayerDNS
	LayerHTTP
	LayerHTTP2
	LayerTLS
	LayerDHCP
	LayerQUIC
	LayerNTP
	LayerSNMP
	LayerSyslog
	LayerSTUN
	LayerMQTT
	LayerRedis
	LayerPostgreSQL
	LayerBGP
	LayerSSH
	LayerSSDP
	LayerSIP
	LayerWireGuard
	LayerWebSocket
	LayerWiFi
	LayerRadiotap
	LayerEAPOL
	LayerMySQL
	LayerRADIUS
	LayerNetFlow
	LayerRTP
	LayerRTCP
	LayerCoAP
	LayerModbus
	LayerMQTTSN
	LayerRTSP
	LayerMPEGTS
	LayerH264
	LayerH265
	LayerVP8
	LayerVP9
	LayerAV1
	LayerAAC
	LayerOpus
	LayerAMQP
	LayerBACnet
	LayerOPCUA
	LayerLoRaWAN
	LayerHLS
	LayerGRPC
	LayerProtobuf
	LayerData
)

var layerBits = map[string]LayerMask{
	"eth": LayerEth, "vlan": LayerVLAN, "arp": LayerARP, "ip": LayerIPv4,
	"ipv6": LayerIPv6, "tcp": LayerTCP, "udp": LayerUDP, "sctp": LayerSCTP, "icmp": LayerICMP,
	"icmpv6": LayerICMPv6, "igmp": LayerIGMP, "gre": LayerGRE, "mpls": LayerMPLS,
	"vxlan": LayerVXLAN, "dns": LayerDNS, "http": LayerHTTP, "http2": LayerHTTP2,
	"tls": LayerTLS, "ssl": LayerTLS, "dhcp": LayerDHCP, "quic": LayerQUIC,
	"ntp": LayerNTP, "snmp": LayerSNMP, "syslog": LayerSyslog, "stun": LayerSTUN,
	"mqtt": LayerMQTT, "redis": LayerRedis, "postgresql": LayerPostgreSQL,
	"postgres": LayerPostgreSQL, "bgp": LayerBGP, "ssh": LayerSSH, "ssdp": LayerSSDP,
	"sip": LayerSIP, "wireguard": LayerWireGuard, "wg": LayerWireGuard, "websocket": LayerWebSocket, "wifi": LayerWiFi, "radiotap": LayerRadiotap, "eapol": LayerEAPOL,
	"mysql": LayerMySQL, "radius": LayerRADIUS, "netflow": LayerNetFlow, "rtp": LayerRTP, "rtcp": LayerRTCP, "coap": LayerCoAP, "modbus": LayerModbus, "mqttsn": LayerMQTTSN, "rtsp": LayerRTSP, "mpegts": LayerMPEGTS, "h264": LayerH264, "h265": LayerH265, "vp8": LayerVP8, "vp9": LayerVP9, "av1": LayerAV1, "aac": LayerAAC, "opus": LayerOpus, "amqp": LayerAMQP, "bacnet": LayerBACnet, "opcua": LayerOPCUA, "lorawan": LayerLoRaWAN, "hls": LayerHLS, "grpc": LayerGRPC, "protobuf": LayerProtobuf, "data": LayerData,
	"ip6": LayerIPv6, "icmp6": LayerICMPv6,
}

// LayerBit returns the bit for a layer name, or 0 if unknown.
func LayerBit(name string) LayerMask { return layerBits[name] }

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

	LinkType  LinkType
	Layers    []string
	LayerMask LayerMask

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
	if bit := LayerBit(name); bit != 0 && m.LayerMask != 0 {
		return m.LayerMask&bit != 0
	}
	for _, l := range m.Layers {
		if l == name {
			return true
		}
	}
	return false
}
