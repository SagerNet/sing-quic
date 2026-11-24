package hysteria

import (
	"crypto/sha256"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
)

const xplusSaltLen = 16

type XPlusCodec struct {
	key        []byte
	randAccess sync.Mutex
	rand       *rand.Rand
}

func NewXPlusCodec(key []byte) *XPlusCodec {
	return &XPlusCodec{
		key:  key[:len(key):len(key)],
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (c *XPlusCodec) Encode(b []byte, write func(datagram []byte) error) error {
	buffer := buf.NewSize(xplusSaltLen + len(b))
	defer buffer.Release()
	salt := buffer.Extend(xplusSaltLen)
	c.randAccess.Lock()
	_, _ = c.rand.Read(salt)
	c.randAccess.Unlock()
	key := sha256.Sum256(append(c.key, salt...))
	data := buffer.Extend(len(b))
	for i := range b {
		data[i] = b[i] ^ key[i%sha256.Size]
	}
	return write(buffer.Bytes())
}

func (c *XPlusCodec) Decode(b []byte, _ net.Addr) ([]byte, bool) {
	if len(b) <= xplusSaltLen {
		return nil, false
	}
	key := sha256.Sum256(append(c.key, b[:xplusSaltLen]...))
	data := b[xplusSaltLen:]
	for i := range data {
		data[i] ^= key[i%sha256.Size]
	}
	return data, true
}

func NewXPlusClientConn(conn net.Conn, key []byte) net.Conn {
	return &XPlusClientConn{
		Conn: conn,
		key:  key[:len(key):len(key)],
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

type XPlusClientConn struct {
	net.Conn
	key        []byte
	randAccess sync.Mutex
	rand       *rand.Rand
}

func (c *XPlusClientConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if err != nil {
		return
	} else if n < xplusSaltLen {
		n = 0
		return
	}
	key := sha256.Sum256(append(c.key, p[:xplusSaltLen]...))
	for i := range n - xplusSaltLen {
		p[i] = p[xplusSaltLen+i] ^ key[i%sha256.Size]
	}
	n -= xplusSaltLen
	return
}

func (c *XPlusClientConn) Write(p []byte) (n int, err error) {
	buffer := buf.NewSize(len(p) + xplusSaltLen)
	defer buffer.Release()
	salt := buffer.Extend(xplusSaltLen)
	c.randAccess.Lock()
	_, _ = c.rand.Read(salt)
	c.randAccess.Unlock()
	key := sha256.Sum256(append(c.key, salt...))
	for i := range p {
		common.Must(buffer.WriteByte(p[i] ^ key[i%sha256.Size]))
	}
	_, err = c.Conn.Write(buffer.Bytes())
	if err != nil {
		return
	}
	return len(p), nil
}

func (c *XPlusClientConn) Upstream() any {
	return c.Conn
}
