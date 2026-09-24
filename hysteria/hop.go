package hysteria

import (
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	packetQueueSize    = 1024
	udpBufferSize      = 2048
	defaultHopInterval = 30 * time.Second
)

type HopConn struct {
	dialFunc    func(M.Socksaddr) (net.Conn, error)
	destination M.Socksaddr
	ports       []uint16
	interval    time.Duration
	intervalMax time.Duration
	access      sync.Mutex
	prevConn    net.Conn
	currentConn net.Conn
	portIndex   int
	packetChan  chan *buf.Buffer
	errChan     chan error
	doneChan    chan struct{}
	done        bool
}

func NewHopConn(
	dialFunc func(M.Socksaddr) (net.Conn, error),
	destination M.Socksaddr,
	ports []uint16,
	interval time.Duration,
	intervalMax time.Duration,
) (*HopConn, error) {
	if interval == 0 && intervalMax == 0 {
		interval = defaultHopInterval
		intervalMax = defaultHopInterval
	} else if intervalMax == 0 {
		intervalMax = interval
	} else if interval == 0 {
		return nil, E.New("min and max hop interval must both be set")
	} else if interval > intervalMax {
		return nil, E.New("min hop interval must not be greater than max hop interval")
	}
	if interval < 5*time.Second {
		return nil, E.New("hop interval must be at least 5 seconds")
	}
	hopConn := &HopConn{
		dialFunc:    dialFunc,
		destination: destination,
		ports:       ports,
		interval:    interval,
		intervalMax: intervalMax,
		packetChan:  make(chan *buf.Buffer, packetQueueSize),
		errChan:     make(chan error, 1),
		doneChan:    make(chan struct{}),
	}
	nextAddr := hopConn.nextAddr()
	currentConn, err := dialFunc(nextAddr)
	if err != nil {
		return nil, err
	}
	if destination.IsFqdn() {
		remoteAddr := M.SocksaddrFromNet(currentConn.RemoteAddr()).Unwrap()
		if remoteAddr.IsIP() {
			if remoteAddr.Port != nextAddr.Port {
				currentConn.Close()
				return nil, E.New("port hopping: remote address ", remoteAddr, " does not match destination ", nextAddr)
			}
			hopConn.destination = M.Socksaddr{Addr: remoteAddr.Addr}
		}
	}
	hopConn.currentConn = currentConn
	qtls.SetDesiredBufferSizes(currentConn)
	go hopConn.recvLoop(currentConn)
	go hopConn.hopLoop()
	return hopConn, nil
}

func (c *HopConn) nextAddr() M.Socksaddr {
	c.portIndex = rand.Intn(len(c.ports))
	return M.Socksaddr{
		Addr: c.destination.Addr,
		Fqdn: c.destination.Fqdn,
		Port: c.ports[c.portIndex],
	}
}

func (c *HopConn) recvLoop(conn net.Conn) {
	for {
		buffer := buf.NewSize(udpBufferSize)
		n, err := conn.Read(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Only pass through timeout errors here, not permanent errors
				// like connection closed. Connection close is normal as we close
				// the old connection to exit this loop every time we hop.
				//
				// quic-go sets a past read deadline on transport teardown, which
				// reaches the recvLoops of both prevConn and currentConn; errChan
				// only has room for one, so the send must abort on close.
				select {
				case c.errChan <- netErr:
				case <-c.doneChan:
				}
			}
			return
		}
		buffer.Truncate(n)
		select {
		case c.packetChan <- buffer:
		default:
			buffer.Release()
		}
	}
}

func (c *HopConn) nextHopInterval() time.Duration {
	if c.interval == c.intervalMax {
		return c.interval
	}
	return c.interval + time.Duration(rand.Int63n(int64(c.intervalMax-c.interval)+1))
}

func (c *HopConn) hopLoop() {
	timer := time.NewTimer(c.nextHopInterval())
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			c.hop()
			timer.Reset(c.nextHopInterval())
		case <-c.doneChan:
			return
		}
	}
}

func (c *HopConn) hop() {
	c.access.Lock()
	if c.done {
		c.access.Unlock()
		return
	}
	nextAddr := c.nextAddr()
	c.access.Unlock()

	newConn, err := c.dialFunc(nextAddr)
	if err != nil {
		return
	}

	var oldPrevConn net.Conn
	c.access.Lock()
	if c.done {
		c.access.Unlock()
		_ = newConn.Close()
		return
	}
	oldPrevConn = c.prevConn
	c.prevConn = c.currentConn
	c.currentConn = newConn
	c.access.Unlock()

	if oldPrevConn != nil {
		_ = oldPrevConn.Close()
	}
	qtls.SetDesiredBufferSizes(newConn)
	go c.recvLoop(newConn)
}

func (c *HopConn) Read(b []byte) (n int, err error) {
	for {
		select {
		case packet := <-c.packetChan:
			n = copy(b, packet.Bytes())
			packet.Release()
			return n, nil
		case err = <-c.errChan:
			return 0, err
		case <-c.doneChan:
			return 0, net.ErrClosed
		}
	}
}

func (c *HopConn) Write(b []byte) (n int, err error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.done {
		return 0, net.ErrClosed
	}
	return c.currentConn.Write(b)
}

func (c *HopConn) Close() error {
	c.access.Lock()
	if c.done {
		c.access.Unlock()
		return nil
	}
	c.done = true
	close(c.doneChan)
	prevConn := c.prevConn
	currentConn := c.currentConn
	c.access.Unlock()

	if prevConn != nil {
		_ = prevConn.Close()
	}
	var err error
	if currentConn != nil {
		err = currentConn.Close()
	}
	return err
}

func (c *HopConn) LocalAddr() net.Addr {
	c.access.Lock()
	defer c.access.Unlock()
	return c.currentConn.LocalAddr()
}

func (c *HopConn) RemoteAddr() net.Addr {
	return c.destination.UDPAddr()
}

func (c *HopConn) SetDeadline(t time.Time) error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.prevConn != nil {
		_ = c.prevConn.SetDeadline(t)
	}
	return c.currentConn.SetDeadline(t)
}

func (c *HopConn) SetReadDeadline(t time.Time) error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.prevConn != nil {
		_ = c.prevConn.SetReadDeadline(t)
	}
	return c.currentConn.SetReadDeadline(t)
}

func (c *HopConn) SetWriteDeadline(t time.Time) error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.prevConn != nil {
		_ = c.prevConn.SetWriteDeadline(t)
	}
	return c.currentConn.SetWriteDeadline(t)
}
