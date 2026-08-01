package hysteria2

import (
	"net"
	"os"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/blake2b"
)

const salamanderSaltLen = 8

const ObfsTypeSalamander = "salamander"

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
		return
	}
	key := blake2b.Sum256(append(s.password, p[:salamanderSaltLen]...))
	for index, c := range p[salamanderSaltLen:n] {
		p[index] = c ^ key[index%blake2b.Size256]
	}
	return n - salamanderSaltLen, addr, nil
}

func (s *SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := buf.NewSize(len(p) + salamanderSaltLen)
	defer buffer.Release()
	buffer.WriteRandom(salamanderSaltLen)
	key := blake2b.Sum256(append(s.password, buffer.Bytes()...))
	for index, c := range p {
		common.Must(buffer.WriteByte(c ^ key[index%blake2b.Size256]))
	}
	_, err = s.PacketConn.WriteTo(buffer.Bytes(), addr)
	if err != nil {
		return
	}
	return len(p), nil
}

func (s *SalamanderPacketConn) Upstream() any {
	return s.PacketConn
}

func (s *SalamanderPacketConn) SetReadBuffer(bytes int) error {
	return trySetReadBuffer(s.PacketConn, bytes)
}

func (s *SalamanderPacketConn) SetWriteBuffer(bytes int) error {
	return trySetWriteBuffer(s.PacketConn, bytes)
}

func trySetReadBuffer(conn net.PacketConn, bytes int) error {
	udpConn, isUDPConn := common.Cast[interface {
		SetReadBuffer(bytes int) error
	}](conn)
	if !isUDPConn {
		return os.ErrInvalid
	}
	return udpConn.SetReadBuffer(bytes)
}

func trySetWriteBuffer(conn net.PacketConn, bytes int) error {
	udpConn, isUDPConn := common.Cast[interface {
		SetWriteBuffer(bytes int) error
	}](conn)
	if !isUDPConn {
		return os.ErrInvalid
	}
	return udpConn.SetWriteBuffer(bytes)
}

type VectorisedSalamanderPacketConn struct {
	SalamanderPacketConn
	writer N.VectorisedPacketWriter
}

func (s *VectorisedSalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := buf.NewSize(salamanderSaltLen)
	buffer.WriteRandom(salamanderSaltLen)
	key := blake2b.Sum256(append(s.password, buffer.Bytes()...))
	for i := range p {
		p[i] ^= key[i%blake2b.Size256]
	}
	err = s.writer.WriteVectorisedPacket([]*buf.Buffer{buffer, buf.As(p)}, M.SocksaddrFromNet(addr))
	if err != nil {
		return
	}
	return len(p), nil
}

func (s *VectorisedSalamanderPacketConn) WriteVectorisedPacket(buffers []*buf.Buffer, destination M.Socksaddr) error {
	header := buf.NewSize(salamanderSaltLen)
	defer header.Release()
	header.WriteRandom(salamanderSaltLen)
	key := blake2b.Sum256(append(s.password, header.Bytes()...))
	var bufferIndex int
	for _, buffer := range buffers {
		content := buffer.Bytes()
		for index, c := range content {
			content[bufferIndex+index] = c ^ key[bufferIndex+index%blake2b.Size256]
		}
		bufferIndex += len(content)
	}
	return s.writer.WriteVectorisedPacket(append([]*buf.Buffer{header}, buffers...), destination)
}

type SalamanderConn struct {
	net.Conn
	password []byte
}

func NewSalamanderClientConn(conn net.Conn, password []byte) net.Conn {
	writer, isVectorised := bufio.CreateVectorisedWriter(conn)
	if isVectorised {
		return &VectorisedSalamanderConn{
			SalamanderConn: SalamanderConn{
				Conn:     conn,
				password: password[:len(password):len(password)],
			},
			writer: writer,
		}
	} else {
		return &SalamanderConn{
			Conn:     conn,
			password: password[:len(password):len(password)],
		}
	}
}

func (s *SalamanderConn) Read(p []byte) (n int, err error) {
	n, err = s.Conn.Read(p)
	if err != nil {
		return
	}
	if n <= salamanderSaltLen {
		return
	}
	key := blake2b.Sum256(append(s.password, p[:salamanderSaltLen]...))
	for index, c := range p[salamanderSaltLen:n] {
		p[index] = c ^ key[index%blake2b.Size256]
	}
	return n - salamanderSaltLen, nil
}

func (s *SalamanderConn) Write(p []byte) (n int, err error) {
	buffer := buf.NewSize(len(p) + salamanderSaltLen)
	defer buffer.Release()
	buffer.WriteRandom(salamanderSaltLen)
	key := blake2b.Sum256(append(s.password, buffer.Bytes()...))
	for index, c := range p {
		common.Must(buffer.WriteByte(c ^ key[index%blake2b.Size256]))
	}
	_, err = s.Conn.Write(buffer.Bytes())
	if err != nil {
		return
	}
	return len(p), nil
}

func (s *SalamanderConn) Upstream() any {
	return s.Conn
}

type VectorisedSalamanderConn struct {
	SalamanderConn
	writer N.VectorisedWriter
}

func (s *VectorisedSalamanderConn) Write(p []byte) (n int, err error) {
	buffer := buf.NewSize(salamanderSaltLen)
	defer buffer.Release()
	buffer.WriteRandom(salamanderSaltLen)
	key := blake2b.Sum256(append(s.password, buffer.Bytes()...))
	for i := range p {
		p[i] ^= key[i%blake2b.Size256]
	}
	_, err = bufio.WriteVectorised(s.writer, [][]byte{buffer.Bytes(), p})
	if err != nil {
		return
	}
	return len(p), nil
}
