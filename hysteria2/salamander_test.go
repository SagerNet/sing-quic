package hysteria2

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// salamanderTestPacketConn is a loopback PacketConn whose reads are scripted,
// so the runt-datagram boundary can be exercised without a real socket.
type salamanderTestPacketConn struct {
	reads  []salamanderRead
	writes [][]byte
}

type salamanderRead struct {
	data []byte
	addr net.Addr
	err  error
}

func (c *salamanderTestPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.reads) == 0 {
		return 0, nil, errors.New("no more reads")
	}
	read := c.reads[0]
	c.reads = c.reads[1:]
	if read.err != nil {
		return 0, read.addr, read.err
	}
	return copy(p, read.data), read.addr, nil
}

func (c *salamanderTestPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *salamanderTestPacketConn) Close() error                       { return nil }
func (c *salamanderTestPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *salamanderTestPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *salamanderTestPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *salamanderTestPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func newSalamanderTestConn(reads ...salamanderRead) (*SalamanderPacketConn, *salamanderTestPacketConn) {
	raw := &salamanderTestPacketConn{reads: reads}
	return NewSalamanderConn(raw, []byte("test-password")).(*SalamanderPacketConn), raw
}

func TestSalamanderReadFromRuntDatagrams(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	cases := []struct {
		name string
		size int
	}{
		{"zero", 0},
		{"salt-1", salamanderSaltLen - 1},
		{"salt", salamanderSaltLen},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := &salamanderTestPacketConn{reads: []salamanderRead{{data: make([]byte, tc.size), addr: addr}}}
			conn := NewSalamanderConn(raw, []byte("test-password")).(*SalamanderPacketConn)
			p := make([]byte, 64)
			n, gotAddr, err := conn.ReadFrom(p)
			if err != nil {
				t.Fatalf("ReadFrom(%d bytes) error: %v", tc.size, err)
			}
			if n != 0 {
				t.Fatalf("ReadFrom(%d bytes) returned n=%d, want 0 (a runt datagram must not expose salt bytes)", tc.size, n)
			}
			if gotAddr == nil || gotAddr.String() != addr.String() {
				t.Fatalf("ReadFrom(%d bytes) address = %v, want %v", tc.size, gotAddr, addr)
			}
		})
	}
}

func TestSalamanderReadFromPayloadBoundaries(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 443}
	payload := []byte("boundary-payload")

	raw := &salamanderTestPacketConn{}
	writer := NewSalamanderConn(raw, []byte("test-password")).(*SalamanderPacketConn)
	if n, err := writer.WriteTo(payload, addr); err != nil || n != len(payload) {
		t.Fatalf("WriteTo = %d, %v; want %d, nil", n, err, len(payload))
	}
	if len(raw.writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(raw.writes))
	}

	for _, size := range []int{salamanderSaltLen + 1, salamanderSaltLen + len(payload)} {
		data := append([]byte(nil), raw.writes[0][:size]...)
		raw.reads = append(raw.reads, salamanderRead{data: data, addr: addr})
	}
	reader := NewSalamanderConn(raw, []byte("test-password")).(*SalamanderPacketConn)

	p := make([]byte, 64)
	n, _, err := reader.ReadFrom(p)
	if err != nil {
		t.Fatalf("salt+1 read: %v", err)
	}
	if n != 1 {
		t.Fatalf("salt+1 read n=%d, want 1", n)
	}
	n, _, err = reader.ReadFrom(p)
	if err != nil {
		t.Fatalf("full payload read: %v", err)
	}
	if n != len(payload) || !bytes.Equal(p[:n], payload) {
		t.Fatalf("full payload = %q (n=%d), want %q", p[:n], n, payload)
	}
}

func TestSalamanderReadFromRuntThenValidAndError(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 443}
	payload := []byte("after-runt")
	raw := &salamanderTestPacketConn{}
	writer := NewSalamanderConn(raw, []byte("test-password")).(*SalamanderPacketConn)
	if _, err := writer.WriteTo(payload, addr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	raw.reads = []salamanderRead{
		{data: make([]byte, salamanderSaltLen), addr: addr},
		{data: make([]byte, 1), addr: addr, err: errors.New("transient")},
		{data: raw.writes[0], addr: addr},
	}
	reader := NewSalamanderConn(raw, []byte("test-password")).(*SalamanderPacketConn)
	p := make([]byte, 64)
	if n, _, err := reader.ReadFrom(p); err != nil || n != 0 {
		t.Fatalf("runt read = %d, %v; want 0, nil", n, err)
	}
	if _, _, err := reader.ReadFrom(p); err == nil || err.Error() != "transient" {
		t.Fatalf("error read = %v, want transient", err)
	}
	n, _, err := reader.ReadFrom(p)
	if err != nil || n != len(payload) || !bytes.Equal(p[:n], payload) {
		t.Fatalf("valid read after runt/error = %q (n=%d), %v", p[:n], n, err)
	}
}
