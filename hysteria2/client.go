package hysteria2

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-quic"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"
)

var (
	_ N.Dialer        = (*Client)(nil)
	_ N.PayloadDialer = (*Client)(nil)
)

type Client struct {
	ctx                context.Context
	dialer             N.Dialer
	logger             logger.Logger
	brutalDebug        bool
	serverAddr         M.Socksaddr
	sendBPS            uint64
	receiveBPS         uint64
	salamanderPassword string
	password           string
	tlsConfig          aTLS.Config
	quicConfig         *quic.Config
	udpDisabled        bool

	connAccess sync.RWMutex
	conn       *clientQUICConnection
}

type ClientOptions struct {
	Context            context.Context
	Dialer             N.Dialer
	Logger             logger.Logger
	BrutalDebug        bool
	ServerAddress      M.Socksaddr
	SendBPS            uint64
	ReceiveBPS         uint64
	SalamanderPassword string
	Password           string
	TLSConfig          aTLS.Config
	UDPDisabled        bool
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                !options.UDPDisabled,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	return &Client{
		ctx:                options.Context,
		dialer:             options.Dialer,
		logger:             options.Logger,
		brutalDebug:        options.BrutalDebug,
		serverAddr:         options.ServerAddress,
		sendBPS:            options.SendBPS,
		receiveBPS:         options.ReceiveBPS,
		salamanderPassword: options.SalamanderPassword,
		password:           options.Password,
		tlsConfig:          options.TLSConfig,
		quicConfig:         quicConfig,
		udpDisabled:        options.UDPDisabled,
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
	if c.salamanderPassword != "" {
		packetConn = NewSalamanderConn(packetConn, []byte(c.salamanderPassword))
	}
	var quicConn quic.EarlyConnection
	http3Transport, err := qtls.CreateTransport(packetConn, &quicConn, c.serverAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	protocol.AuthRequestToHeader(request.Header, protocol.AuthRequest{Auth: c.password, Rx: c.receiveBPS})
	response, err := http3Transport.RoundTrip(request.WithContext(ctx))
	if err != nil {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		udpConn.Close()
		return nil, err
	}
	if response.StatusCode != protocol.StatusAuthOK {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		udpConn.Close()
		return nil, E.New("authentication failed, status code: ", response.StatusCode)
	}
	response.Body.Close()
	authResponse := protocol.AuthResponseFromHeader(response.Header)
	actualTx := authResponse.Rx
	if actualTx == 0 || actualTx > c.sendBPS {
		actualTx = c.sendBPS
	}
	if !authResponse.RxAuto && actualTx > 0 {
		quicConn.SetCongestionControl(hyCC.NewBrutalSender(actualTx, c.brutalDebug, c.logger))
	} else {
		timeFunc := ntp.TimeFuncFromContext(c.ctx)
		if timeFunc == nil {
			timeFunc = time.Now
		}
		quicConn.SetCongestionControl(congestion_meta2.NewBbrSender(
			congestion_meta2.DefaultClock{TimeFunc: timeFunc},
			congestion.ByteCount(quicConn.Config().InitialPacketSize),
			congestion.ByteCount(congestion_meta1.InitialCongestionWindow),
		))
	}
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     udpConn,
		connDone:    make(chan struct{}),
		udpDisabled: !authResponse.UDPEnabled,
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
		buffer := protocol.WriteTCPRequest(destination.String(), payloads)
		defer buffer.Release()
		_, err = stream.Write(buffer.Bytes())
		if err != nil {
			return nil, baderror.WrapQUIC(err)
		}
		status, errorMessage, err := protocol.ReadTCPResponse(stream)
		if err != nil {
			return nil, baderror.WrapQUIC(err)
		}
		if !status {
			return nil, E.New("remote error: ", errorMessage)
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
				buf.ReleaseMulti(payloads)
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
	var sessionID uint32
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, sessionID)
		conn.udpAccess.Unlock()
	})
	conn.udpAccess.Lock()
	sessionID = conn.udpSessionID
	conn.udpSessionID++
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	clientPacketConn.sessionID = sessionID
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
	quicConn     quic.Connection
	rawConn      io.Closer
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	udpDisabled  bool
	udpAccess    sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32
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

func (c *clientConn) Upstream() any {
	return c.Stream
}
