package realm

import (
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-quic/hysteria2/internal/stun"
	M "github.com/sagernet/sing/common/metadata"
)

type PunchPacketEvent struct {
	AttemptID string
	From      netip.AddrPort
	Type      byte
}

type STUNPacketEvent struct {
	Message *stun.Message
	Address netip.AddrPort
}

type PunchPacketConn struct {
	net.PacketConn
	access     sync.RWMutex
	attempts   map[string]PunchMetadata
	events     chan PunchPacketEvent
	stunEvents chan STUNPacketEvent
}

func NewPunchPacketConn(conn net.PacketConn, eventBuffer int) *PunchPacketConn {
	return &PunchPacketConn{
		PacketConn: conn,
		attempts:   make(map[string]PunchMetadata),
		events:     make(chan PunchPacketEvent, eventBuffer),
		stunEvents: make(chan STUNPacketEvent, eventBuffer),
	}
}

func (c *PunchPacketConn) InterceptPacket(b []byte, addr net.Addr) bool {
	if stun.IsMessage(b) {
		message, decodeErr := stun.Decode(b)
		address := M.SocksaddrFromNet(addr).Unwrap().AddrPort()
		if decodeErr == nil && address.IsValid() {
			select {
			case c.stunEvents <- STUNPacketEvent{Message: message, Address: address}:
			default:
			}
		}
		return true
	}
	c.access.RLock()
	defer c.access.RUnlock()
	if len(c.attempts) == 0 {
		return false
	}
	from := M.SocksaddrFromNet(addr).Unwrap().AddrPort()
	for attemptID, metadata := range c.attempts {
		packetType, decodeErr := DecodePunchPacket(b, metadata)
		if decodeErr != nil {
			continue
		}
		if from.IsValid() {
			select {
			case c.events <- PunchPacketEvent{AttemptID: attemptID, From: from, Type: packetType}:
			default:
			}
		}
		return true
	}
	return false
}

func (c *PunchPacketConn) AddAttempt(id string, metadata PunchMetadata) {
	c.access.Lock()
	defer c.access.Unlock()
	c.attempts[id] = metadata
}

func (c *PunchPacketConn) RemoveAttempt(id string) {
	c.access.Lock()
	defer c.access.Unlock()
	delete(c.attempts, id)
}

func (c *PunchPacketConn) Events() <-chan PunchPacketEvent {
	return c.events
}

func (c *PunchPacketConn) STUNEvents() <-chan STUNPacketEvent {
	return c.stunEvents
}

func (c *PunchPacketConn) Upstream() any {
	return c.PacketConn
}
