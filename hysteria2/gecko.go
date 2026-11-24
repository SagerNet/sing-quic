package hysteria2

import (
	"crypto/rand"
	"encoding/binary"
	rand2 "math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const ObfsTypeGecko = "gecko"

const (
	geckoFragmentFlag         = 0x80
	geckoHeaderLen            = 5
	geckoMinChunks            = 2
	geckoMaxChunks            = 8
	geckoMaxOnWireSize        = 2048
	geckoDefaultMinPacketSize = 512
	geckoDefaultMaxPacketSize = 1200
	geckoReassemblyTTL        = 8 * time.Second
	geckoMaxReassembly        = 4096
	geckoMaxPerSource         = 8
)

type GeckoCodec struct {
	salamander    *SalamanderCodec
	minPacketSize int
	maxPacketSize int
	msgIDCounter  atomic.Uint32

	reassembly map[geckoReassemblyKey]*geckoReassemblyEntry
	perSource  map[string]int

	lastSweep time.Time
}

type geckoReassemblyKey struct {
	addr  string
	msgID uint8
}

type geckoReassemblyEntry struct {
	chunks   [][]byte
	received int
	total    uint8
	deadline time.Time
}

func NewGeckoCodec(password []byte, minPacketSize, maxPacketSize int) *GeckoCodec {
	return &GeckoCodec{
		salamander:    NewSalamanderCodec(password),
		minPacketSize: minPacketSize,
		maxPacketSize: maxPacketSize,
		reassembly:    make(map[geckoReassemblyKey]*geckoReassemblyEntry),
		perSource:     make(map[string]int),
		lastSweep:     time.Now(),
	}
}

func (g *GeckoCodec) Encode(b []byte, write func(datagram []byte) error) error {
	if len(b) == 0 {
		return nil
	}
	if b[0]&geckoFragmentFlag == 0 {
		return g.salamander.Encode(b, write)
	}
	chunks := geckoMinChunks + rand2.IntN(geckoMaxChunks-geckoMinChunks+1)
	chunkSize := len(b) / chunks
	msgID := uint8(g.msgIDCounter.Add(1))
	for i := 0; i < chunks; i++ {
		start := i * chunkSize
		end := len(b)
		if i < chunks-1 {
			end = start + chunkSize
		}
		chunk := b[start:end]
		padLen := g.randomPadLen(len(chunk))
		frame := make([]byte, geckoHeaderLen+int(padLen)+len(chunk))
		frame[0] = geckoFragmentFlag
		frame[1] = msgID
		frame[2] = byte(i)<<4 | byte(chunks)&0x0f
		binary.BigEndian.PutUint16(frame[3:5], padLen)
		if padLen > 0 {
			_, randErr := rand.Read(frame[geckoHeaderLen : geckoHeaderLen+int(padLen)])
			if randErr != nil {
				return randErr
			}
		}
		copy(frame[geckoHeaderLen+int(padLen):], chunk)
		err := g.salamander.Encode(frame, write)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *GeckoCodec) randomPadLen(chunkLen int) uint16 {
	base := salamanderSaltLen + geckoHeaderLen + chunkLen
	lo := g.minPacketSize
	if base > lo {
		lo = base
	}
	if lo > g.maxPacketSize {
		return 0
	}
	return uint16(lo - base + rand2.IntN(g.maxPacketSize-lo+1))
}

func (g *GeckoCodec) Decode(b []byte, addr net.Addr) ([]byte, bool) {
	data, decoded := g.salamander.Decode(b, addr)
	if !decoded {
		return nil, false
	}
	if data[0]&geckoFragmentFlag == 0 {
		return data, true
	}
	if len(data) < geckoHeaderLen {
		return nil, false
	}
	msgID := data[1]
	chunkIdx := data[2] >> 4
	totalChunks := data[2] & 0x0f
	padLen := binary.BigEndian.Uint16(data[3:5])
	if totalChunks < geckoMinChunks || totalChunks > geckoMaxChunks {
		return nil, false
	}
	if chunkIdx >= totalChunks {
		return nil, false
	}
	payloadStart := geckoHeaderLen + int(padLen)
	if payloadStart > len(data) {
		return nil, false
	}
	chunks, ready := g.acceptChunk(addr, msgID, chunkIdx, totalChunks, data[payloadStart:])
	if !ready {
		return nil, false
	}
	var packetLen int
	for _, chunk := range chunks {
		packetLen += len(chunk)
	}
	if packetLen > cap(b) {
		return nil, false
	}
	packet := b[:0]
	for _, chunk := range chunks {
		packet = append(packet, chunk...)
	}
	return packet, true
}

func (g *GeckoCodec) acceptChunk(addr net.Addr, msgID, chunkIdx, totalChunks uint8, payload []byte) ([][]byte, bool) {
	addrString := addr.String()
	key := geckoReassemblyKey{addr: addrString, msgID: msgID}

	now := time.Now()
	if now.Sub(g.lastSweep) >= geckoReassemblyTTL/2 {
		g.sweepExpired(now)
	}

	entry, loaded := g.reassembly[key]
	if !loaded {
		if g.perSource[addrString] >= geckoMaxPerSource {
			return nil, false
		}
		if len(g.reassembly) >= geckoMaxReassembly {
			g.evictOldest()
		}
		entry = &geckoReassemblyEntry{
			chunks:   make([][]byte, totalChunks),
			total:    totalChunks,
			deadline: time.Now().Add(geckoReassemblyTTL),
		}
		g.reassembly[key] = entry
		g.perSource[addrString]++
	} else if entry.total != totalChunks {
		return nil, false
	}
	if int(chunkIdx) >= len(entry.chunks) || entry.chunks[chunkIdx] != nil {
		return nil, false
	}
	// payload aliases the caller buffer; the next inner read will overwrite it.
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)
	entry.chunks[chunkIdx] = payloadCopy
	entry.received++
	if entry.received < int(entry.total) {
		return nil, false
	}
	g.dropEntry(key)
	return entry.chunks, true
}

func (g *GeckoCodec) dropEntry(key geckoReassemblyKey) {
	_, loaded := g.reassembly[key]
	if !loaded {
		return
	}
	delete(g.reassembly, key)
	g.perSource[key.addr]--
	if g.perSource[key.addr] <= 0 {
		delete(g.perSource, key.addr)
	}
}

func (g *GeckoCodec) evictOldest() {
	var oldestKey geckoReassemblyKey
	var oldestDeadline time.Time
	first := true
	for key, entry := range g.reassembly {
		if first || entry.deadline.Before(oldestDeadline) {
			oldestKey = key
			oldestDeadline = entry.deadline
			first = false
		}
	}
	if !first {
		g.dropEntry(oldestKey)
	}
}

func (g *GeckoCodec) sweepExpired(now time.Time) {
	for key, entry := range g.reassembly {
		if now.After(entry.deadline) {
			g.dropEntry(key)
		}
	}
	g.lastSweep = now
}

type GeckoPacketConn struct {
	net.PacketConn
	codec      *GeckoCodec
	readAccess sync.Mutex
}

func NewGeckoConn(conn net.PacketConn, password []byte, minPacketSize, maxPacketSize int) net.PacketConn {
	return &GeckoPacketConn{
		PacketConn: conn,
		codec:      NewGeckoCodec(password, minPacketSize, maxPacketSize),
	}
}

func (g *GeckoPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	g.readAccess.Lock()
	defer g.readAccess.Unlock()
	for {
		n, addr, err := g.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		packet, decoded := g.codec.Decode(p[:n:len(p)], addr)
		if decoded {
			return copy(p, packet), addr, nil
		}
	}
}

func (g *GeckoPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	err := g.codec.Encode(p, func(datagram []byte) error {
		_, err := g.PacketConn.WriteTo(datagram, addr)
		return err
	})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (g *GeckoPacketConn) Upstream() any {
	return g.PacketConn
}

type GeckoConn struct {
	net.Conn
	minPacketSize int
	maxPacketSize int
	msgIDCounter  atomic.Uint32

	readAccess       sync.Mutex
	reassemblyAccess sync.Mutex
	reassembly       map[uint8]*geckoReassemblyEntry

	lastSweep time.Time
}

func NewGeckoClientConn(conn net.Conn, password []byte, minPacketSize, maxPacketSize int) net.Conn {
	return &GeckoConn{
		Conn:          NewSalamanderClientConn(conn, password),
		minPacketSize: minPacketSize,
		maxPacketSize: maxPacketSize,
		reassembly:    make(map[uint8]*geckoReassemblyEntry),
		lastSweep:     time.Now(),
	}
}

func (g *GeckoConn) Upstream() any {
	return g.Conn
}

func (g *GeckoConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if p[0]&geckoFragmentFlag == 0 {
		return g.Conn.Write(p)
	}
	return g.writeFragmented(p)
}

func (g *GeckoConn) writeFragmented(p []byte) (int, error) {
	chunks := geckoMinChunks + rand2.IntN(geckoMaxChunks-geckoMinChunks+1)
	chunkSize := len(p) / chunks
	msgID := uint8(g.msgIDCounter.Add(1))
	for i := 0; i < chunks; i++ {
		start := i * chunkSize
		end := len(p)
		if i < chunks-1 {
			end = start + chunkSize
		}
		chunk := p[start:end]
		padLen := g.randomPadLen(len(chunk))
		frame := make([]byte, geckoHeaderLen+int(padLen)+len(chunk))
		frame[0] = geckoFragmentFlag
		frame[1] = msgID
		frame[2] = byte(i)<<4 | byte(chunks)&0x0f
		binary.BigEndian.PutUint16(frame[3:5], padLen)
		if padLen > 0 {
			_, randErr := rand.Read(frame[geckoHeaderLen : geckoHeaderLen+int(padLen)])
			if randErr != nil {
				return 0, randErr
			}
		}
		copy(frame[geckoHeaderLen+int(padLen):], chunk)
		_, err := g.Conn.Write(frame)
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (g *GeckoConn) randomPadLen(chunkLen int) uint16 {
	base := salamanderSaltLen + geckoHeaderLen + chunkLen
	lo := g.minPacketSize
	if base > lo {
		lo = base
	}
	if lo > g.maxPacketSize {
		return 0
	}
	return uint16(lo - base + rand2.IntN(g.maxPacketSize-lo+1))
}

func (g *GeckoConn) Read(p []byte) (int, error) {
	g.readAccess.Lock()
	defer g.readAccess.Unlock()
	for {
		n, err := g.Conn.Read(p)
		if err != nil {
			return n, err
		}
		if n == 0 {
			continue
		}
		if p[0]&geckoFragmentFlag == 0 {
			return n, nil
		}
		if n < geckoHeaderLen {
			continue
		}
		msgID := p[1]
		chunkIdx := p[2] >> 4
		totalChunks := p[2] & 0x0f
		padLen := binary.BigEndian.Uint16(p[3:5])
		if totalChunks < geckoMinChunks || totalChunks > geckoMaxChunks {
			continue
		}
		if chunkIdx >= totalChunks {
			continue
		}
		payloadStart := geckoHeaderLen + int(padLen)
		if payloadStart > n {
			continue
		}
		out, ready := g.acceptChunk(msgID, chunkIdx, totalChunks, p[payloadStart:n])
		if !ready {
			continue
		}
		return copy(p, out), nil
	}
}

func (g *GeckoConn) acceptChunk(msgID, chunkIdx, totalChunks uint8, payload []byte) ([]byte, bool) {
	g.reassemblyAccess.Lock()
	defer g.reassemblyAccess.Unlock()

	now := time.Now()
	if now.Sub(g.lastSweep) >= geckoReassemblyTTL/2 {
		g.sweepExpiredLocked(now)
	}

	entry, loaded := g.reassembly[msgID]
	if !loaded {
		if len(g.reassembly) >= geckoMaxPerSource {
			return nil, false
		}
		entry = &geckoReassemblyEntry{
			chunks:   make([][]byte, totalChunks),
			total:    totalChunks,
			deadline: time.Now().Add(geckoReassemblyTTL),
		}
		g.reassembly[msgID] = entry
	} else if entry.total != totalChunks {
		return nil, false
	}
	if int(chunkIdx) >= len(entry.chunks) || entry.chunks[chunkIdx] != nil {
		return nil, false
	}
	// payload aliases the caller buffer; the next inner read will overwrite it.
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)
	entry.chunks[chunkIdx] = payloadCopy
	entry.received++
	if entry.received < int(entry.total) {
		return nil, false
	}
	out := slices.Concat(entry.chunks...)
	delete(g.reassembly, msgID)
	return out, true
}

func (g *GeckoConn) sweepExpiredLocked(now time.Time) {
	for msgID, entry := range g.reassembly {
		if now.After(entry.deadline) {
			delete(g.reassembly, msgID)
		}
	}
	g.lastSweep = now
}
