package hysteria

import (
	"context"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-quic"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

var (
	_ N.Dialer        = (*Client)(nil)
	_ N.PayloadDialer = (*Client)(nil)
)

type Client struct {
	ctx           context.Context
	dialer        N.Dialer
	logger        logger.Logger
	brutalDebug   bool
	serverAddr    M.Socksaddr
	sendBPS       uint64
	receiveBPS    uint64
	xplusPassword string
	password      string
	tlsConfig     aTLS.Config
	quicConfig    *quic.Config
	udpDisabled   bool

	connAccess sync.RWMutex
	conn       *clientQUICConnection
}

type ClientOptions struct {
	Context       context.Context
	Dialer        N.Dialer
	Logger        logger.Logger
	BrutalDebug   bool
	ServerAddress M.Socksaddr
	SendBPS       uint64
	ReceiveBPS    uint64
	XPlusPassword string
	Password      string
	TLSConfig     aTLS.Config
	UDPDisabled   bool

	// Legacy options

	ConnReceiveWindow   uint64
	StreamReceiveWindow uint64
	DisableMTUDiscovery bool
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     DefaultConnReceiveWindow,
		MaxIdleTimeout:                 DefaultMaxIdleTimeout,
		KeepAlivePeriod:                DefaultKeepAlivePeriod,
	}
	if options.StreamReceiveWindow != 0 {
		quicConfig.InitialStreamReceiveWindow = options.StreamReceiveWindow
		quicConfig.MaxStreamReceiveWindow = options.StreamReceiveWindow
	}
	if options.ConnReceiveWindow != 0 {
		quicConfig.InitialConnectionReceiveWindow = options.ConnReceiveWindow
		quicConfig.MaxConnectionReceiveWindow = options.ConnReceiveWindow
	}
	if options.DisableMTUDiscovery {
		quicConfig.DisablePathMTUDiscovery = true
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{DefaultALPN})
	}
	if options.SendBPS == 0 {
		return nil, E.New("missing upload speed")
	} else if options.SendBPS < MinSpeedBPS {
		return nil, E.New("invalid upload speed")
	}
	if options.ReceiveBPS == 0 {
		return nil, E.New("missing download speed")
	} else if options.ReceiveBPS < MinSpeedBPS {
		return nil, E.New("invalid download speed")
	}
	return &Client{
		ctx:           options.Context,
		dialer:        options.Dialer,
		logger:        options.Logger,
		brutalDebug:   options.BrutalDebug,
		serverAddr:    options.ServerAddress,
		sendBPS:       options.SendBPS,
		receiveBPS:    options.ReceiveBPS,
		xplusPassword: options.XPlusPassword,
		password:      options.Password,
		tlsConfig:     options.TLSConfig,
		quicConfig:    quicConfig,
		udpDisabled:   options.UDPDisabled,
	}, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	conn := c.conn
	if conn != nil && conn.active() {
		return conn, nil
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	conn = c.conn
	if conn != nil && conn.active() {
		return conn, nil
	}
	conn, err := c.offerNew(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	udpConn, err := c.dialer.DialContext(c.ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	var packetConn net.PacketConn
	packetConn = bufio.NewUnbindPacketConn(udpConn)
	if c.xplusPassword != "" {
		packetConn = NewXPlusPacketConn(packetConn, []byte(c.xplusPassword))
	}
	quicConn, err := qtls.Dial(c.ctx, packetConn, udpConn.RemoteAddr(), c.tlsConfig, c.quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, err
	}
	controlStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	err = WriteClientHello(controlStream, ClientHello{
		SendBPS: c.sendBPS,
		RecvBPS: c.receiveBPS,
		Auth:    c.password,
	})
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	serverHello, err := ReadServerHello(controlStream)
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	if !serverHello.OK {
		packetConn.Close()
		return nil, E.New("remote error: ", serverHello.Message)
	}
	quicConn.SetCongestionControl(hyCC.NewBrutalSender(uint64(math.Min(float64(serverHello.RecvBPS), float64(c.sendBPS))), c.brutalDebug, c.logger))
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     udpConn,
		connDone:    make(chan struct{}),
		udpDisabled: !quicConn.ConnectionState().SupportsDatagrams,
		udpConnMap:  make(map[uint32]*udpPacketConn),
	}
	if !c.udpDisabled {
		go c.loopMessages(conn)
	}
	c.conn = conn
	return conn, nil
}

func (c *Client) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return c.DialPayloadContext(ctx, network, destination, nil)
	case N.NetworkUDP:
		packetConn, err := c.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Cause(N.ErrUnknownNetwork, network)
	}
}

func (c *Client) DialPayloadContext(ctx context.Context, network string, destination M.Socksaddr, payloads []*buf.Buffer) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		conn, err := c.offer(ctx)
		if err != nil {
			buf.ReleaseMulti(payloads)
			return nil, err
		}
		stream, err := conn.quicConn.OpenStreamSync(ctx)
		if err != nil {
			buf.ReleaseMulti(payloads)
			return nil, err
		}
		buffer := WriteClientRequest(ClientRequest{
			UDP:  false,
			Host: destination.AddrString(),
			Port: destination.Port,
		}, payloads)
		_, err = stream.Write(buffer.Bytes())
		buffer.Release()
		if err != nil {
			return nil, baderror.WrapQUIC(err)
		}
		response, err := ReadServerResponse(stream)
		if err != nil {
			return nil, baderror.WrapQUIC(err)
		}
		if !response.OK {
			return nil, E.New("remote error: ", response.Message)
		}
		return &clientConn{
			Stream:      stream,
			destination: destination,
		}, nil
	case N.NetworkUDP:
		packetConn, err := c.ListenPacket(ctx, destination)
		if err != nil {
			buf.ReleaseMulti(payloads)
			return nil, err
		}
		for _, payload := range payloads {
			_, err = packetConn.WriteTo(payload.Bytes(), destination)
			payload.Release()
			if err != nil {
				return nil, E.Cause(err, "write payload")
			}
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Cause(N.ErrUnknownNetwork, network)
	}
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if c.udpDisabled {
		return nil, os.ErrInvalid
	}
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	if conn.udpDisabled {
		return nil, E.New("UDP disabled by server")
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	buffer := WriteClientRequest(ClientRequest{
		UDP:  true,
		Host: destination.AddrString(),
		Port: destination.Port,
	}, nil)
	_, err = stream.Write(buffer.Bytes())
	buffer.Release()
	if err != nil {
		stream.Close()
		return nil, err
	}
	response, err := ReadServerResponse(stream)
	if err != nil {
		stream.Close()
		return nil, err
	}
	if !response.OK {
		stream.Close()
		return nil, E.New("remote error: ", response.Message)
	}
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		stream.CancelRead(0)
		stream.Close()
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, response.UDPSessionID)
		conn.udpAccess.Unlock()
	})
	conn.udpAccess.Lock()
	if debug.Enabled {
		if _, connExists := conn.udpConnMap[response.UDPSessionID]; connExists {
			stream.Close()
			return nil, E.New("udp session id duplicated")
		}
	}
	conn.udpConnMap[response.UDPSessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	clientPacketConn.sessionID = response.UDPSessionID
	go func() {
		holdBuffer := make([]byte, 1024)
		for {
			_, hErr := stream.Read(holdBuffer)
			if hErr != nil {
				break
			}
		}
		clientPacketConn.closeWithError(E.Cause(net.ErrClosed, "hold stream closed"))
	}()
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	conn := c.conn
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

type clientQUICConnection struct {
	quicConn    quic.Connection
	rawConn     io.Closer
	closeOnce   sync.Once
	connDone    chan struct{}
	connErr     error
	udpDisabled bool
	udpAccess   sync.RWMutex
	udpConnMap  map[uint32]*udpPacketConn
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		close(c.connDone)
		_ = c.quicConn.CloseWithError(0, "")
		_ = c.rawConn.Close()
	})
}

type clientConn struct {
	quic.Stream
	destination M.Socksaddr
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, baderror.WrapQUIC(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	n, err = c.Stream.Write(p)
	return n, baderror.WrapQUIC(err)
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.destination
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
