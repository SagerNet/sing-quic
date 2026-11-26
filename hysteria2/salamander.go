package hysteria2

import (
	"crypto/subtle"
	"net"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/blake2b"
)

const salamanderSaltLen = 8

const ObfsTypeSalamander = "salamander"

type SalamanderCodec struct {
	password []byte
}

func NewSalamanderCodec(password []byte) *SalamanderCodec {
	return &SalamanderCodec{password: password[:len(password):len(password)]}
}

func (c *SalamanderCodec) Encode(b []byte, write func(datagram []byte) error) error {
	buffer := buf.NewSize(salamanderSaltLen + len(b))
	defer buffer.Release()
	salt := buffer.WriteRandom(salamanderSaltLen)
	key := blake2b.Sum256(append(c.password, salt...))
	salamanderXOR(buffer.Extend(len(b)), b, &key, 0)
	return write(buffer.Bytes())
}

func (c *SalamanderCodec) Decode(b []byte, _ net.Addr) ([]byte, bool) {
	if len(b) <= salamanderSaltLen {
		return nil, false
	}
	key := blake2b.Sum256(append(c.password, b[:salamanderSaltLen]...))
	data := b[salamanderSaltLen:]
	salamanderXOR(data, data, &key, 0)
	return data, true
}

func salamanderXOR(dst, src []byte, key *[blake2b.Size256]byte, keyOffset int) int {
	for len(src) > 0 {
		n := subtle.XORBytes(dst, src, key[keyOffset:])
		dst, src = dst[n:], src[n:]
		keyOffset = (keyOffset + n) % blake2b.Size256
	}
	return keyOffset
}

type SalamanderPacketConn struct {
	net.PacketConn
	password []byte
}

func NewSalamanderConn(conn net.PacketConn, password []byte) net.PacketConn {
	writer, isVectorised := bufio.CreateVectorisedPacketWriter(conn)
	if isVectorised {
		return &VectorisedSalamanderPacketConn{
			SalamanderPacketConn: SalamanderPacketConn{
				PacketConn: conn,
				password:   password[:len(password):len(password)],
			},
			writer: writer,
		}
	} else {
		return &SalamanderPacketConn{
			PacketConn: conn,
			password:   password[:len(password):len(password)],
		}
	}
}

func (s *SalamanderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	if err != nil {
		return
	}
	if n <= salamanderSaltLen {
		return 0, addr, nil
	}
	key := blake2b.Sum256(append(s.password, p[:salamanderSaltLen]...))
	data := p[:copy(p, p[salamanderSaltLen:n])]
	salamanderXOR(data, data, &key, 0)
	return n - salamanderSaltLen, addr, nil
}

func (s *SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := buf.NewSize(len(p) + salamanderSaltLen)
	defer buffer.Release()
	key := blake2b.Sum256(append(s.password, buffer.WriteRandom(salamanderSaltLen)...))
	salamanderXOR(buffer.Extend(len(p)), p, &key, 0)
	_, err = s.PacketConn.WriteTo(buffer.Bytes(), addr)
	if err != nil {
		return
	}
	return len(p), nil
}

func (s *SalamanderPacketConn) Upstream() any {
	return s.PacketConn
}

type VectorisedSalamanderPacketConn struct {
	SalamanderPacketConn
	writer N.VectorisedPacketWriter
}

func (s *VectorisedSalamanderPacketConn) WriteVectorisedPacket(buffers []*buf.Buffer, destination M.Socksaddr) error {
	header := buf.NewSize(salamanderSaltLen)
	header.WriteRandom(salamanderSaltLen)
	key := blake2b.Sum256(append(s.password, header.Bytes()...))
	var keyOffset int
	for _, buffer := range buffers {
		content := buffer.Bytes()
		keyOffset = salamanderXOR(content, content, &key, keyOffset)
	}
	return s.writer.WriteVectorisedPacket(append([]*buf.Buffer{header}, buffers...), destination)
}

type SalamanderConn struct {
	net.Conn
	password []byte
}

func NewSalamanderClientConn(conn net.Conn, password []byte) net.Conn {
	return &SalamanderConn{
		Conn:     conn,
		password: password[:len(password):len(password)],
	}
}

func (s *SalamanderConn) Read(p []byte) (n int, err error) {
	n, err = s.Conn.Read(p)
	if err != nil {
		return
	}
	if n <= salamanderSaltLen {
		return 0, nil
	}
	key := blake2b.Sum256(append(s.password, p[:salamanderSaltLen]...))
	data := p[:copy(p, p[salamanderSaltLen:n])]
	salamanderXOR(data, data, &key, 0)
	return n - salamanderSaltLen, nil
}

func (s *SalamanderConn) Write(p []byte) (n int, err error) {
	buffer := buf.NewSize(len(p) + salamanderSaltLen)
	defer buffer.Release()
	key := blake2b.Sum256(append(s.password, buffer.WriteRandom(salamanderSaltLen)...))
	salamanderXOR(buffer.Extend(len(p)), p, &key, 0)
	_, err = s.Conn.Write(buffer.Bytes())
	if err != nil {
		return
	}
	return len(p), nil
}

func (s *SalamanderConn) Upstream() any {
	return s.Conn
}
