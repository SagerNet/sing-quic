package tuic

import (
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ClientOptions struct {
	Context           context.Context
	Dialer            N.Dialer
	ServerAddress     M.Socksaddr
	TLSConfig         aTLS.Config
	QUICOptions       qtls.QUICOptions
	UUID              [16]byte
	Password          string
	CongestionControl string
	UDPStream         bool
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration
}

type Client struct {
	ctx               context.Context
	dialer            N.Dialer
	serverAddr        M.Socksaddr
	tlsConfig         aTLS.Config
	quicConfig        *quic.Config
	uuid              [16]byte
	password          string
	congestionControl string
	udpStream         bool
	zeroRTTHandshake  bool
	heartbeat         time.Duration

	connAccess sync.Mutex
	conn       *clientQUICConnection
	closeIdle  atomic.Bool
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         true,
		MaxIncomingUniStreams:   1 << 60,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	switch options.CongestionControl {
	case "":
		options.CongestionControl = "cubic"
	case "cubic", "new_reno", "bbr":
	default:
		return nil, E.New("unknown congestion control algorithm: ", options.CongestionControl)
	}
	return &Client{
		ctx:               options.Context,
		dialer:            options.Dialer,
		serverAddr:        options.ServerAddress,
		tlsConfig:         options.TLSConfig,
		quicConfig:        quicConfig,
		uuid:              options.UUID,
		password:          options.Password,
		congestionControl: options.CongestionControl,
		udpStream:         options.UDPStream,
		zeroRTTHandshake:  options.ZeroRTTHandshake,
		heartbeat:         options.Heartbeat,
	}, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	conn := c.conn
	if conn != nil && conn.active() {
		c.connAccess.Unlock()
		return conn, nil
	}
	pending := c.pending
	if pending != nil {
		c.connAccess.Unlock()
		select {
		case <-pending.done:
			return pending.conn, pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// A pending offer is shared by concurrent callers. Do not derive offerCtx
	// from the foreground request ctx: a timed-out request must stop waiting for
	// the shared result, but it must not tear down the background QUIC dial that
	// may still be reused by later requests. The connection attempt is owned by
	// the client lifetime context instead.
	offerCtx := c.ctx
	if offerCtx == nil {
		offerCtx = context.Background()
	}
	offerCtx, cancel := context.WithCancelCause(offerCtx)
	pending = &clientOffer{
		done:   make(chan struct{}),
		cancel: cancel,
	}
	c.pending = pending
	c.connAccess.Unlock()

	go c.completeOffer(pending, offerCtx)

	select {
	case <-pending.done:
		return pending.conn, pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) completeOffer(pending *clientOffer, offerCtx context.Context) {
	conn, err := c.offerNew(offerCtx)
	pending.cancel(nil)

	discardErr := err
	shouldDiscard := false
	c.connAccess.Lock()
	if pending.discarded {
		shouldDiscard = true
		if pending.cause != nil {
			discardErr = pending.cause
		}
		pending.err = discardErr
	} else {
		pending.conn = conn
		pending.err = err
		if err == nil {
			c.conn = conn
		}
	}
	if c.pending == pending {
		c.pending = nil
	}
	close(pending.done)
	c.connAccess.Unlock()

	if shouldDiscard && conn != nil {
		conn.closeWithError(discardErr)
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	udpConn, err := c.dialer.DialContext(ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	var quicConn *quic.Conn
	if c.zeroRTTHandshake {
		quicConn, err = qtls.DialEarly(ctx, udpConn, c.tlsConfig, c.quicConfig)
	} else {
		quicConn, err = qtls.Dial(ctx, udpConn, c.tlsConfig, c.quicConfig)
	}
	if err != nil {
		udpConn.Close()
		return nil, E.Cause(err, "open connection")
	}
	setCongestion(c.ctx, quicConn, c.congestionControl)
	conn := &clientQUICConnection{
		quicConn:   quicConn,
		rawConn:    udpConn,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint16]*udpPacketConn),
		closeIdle:  &c.closeIdle,
	}
	go func() {
		hErr := c.clientHandshake(quicConn)
		if hErr != nil {
			conn.closeWithError(hErr)
		}
	}()
	if c.udpStream {
		go c.loopUniStreams(conn)
	}
	go c.loopMessages(conn)
	go c.loopHeartbeats(conn)
	return conn, nil
}

func (c *Client) clientHandshake(conn *quic.Conn) error {
	authStream, err := conn.OpenUniStream()
	if err != nil {
		return E.Cause(err, "open handshake stream")
	}
	defer authStream.Close()
	handshakeState := conn.ConnectionState()
	tuicAuthToken, err := handshakeState.TLS.ExportKeyingMaterial(string(c.uuid[:]), []byte(c.password), 32)
	if err != nil {
		return E.Cause(err, "export keying material")
	}
	authRequest := buf.NewSize(AuthenticateLen)
	authRequest.WriteByte(Version)
	authRequest.WriteByte(CommandAuthenticate)
	authRequest.Write(c.uuid[:])
	authRequest.Write(tuicAuthToken)
	return common.Error(authStream.Write(authRequest.Bytes()))
}

func (c *Client) loopHeartbeats(conn *clientQUICConnection) {
	ticker := time.NewTicker(c.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-conn.connDone:
			return
		case <-ticker.C:
			err := conn.quicConn.SendDatagram([]byte{Version, CommandHeartbeat})
			if err != nil {
				conn.closeWithError(E.Cause(err, "send heartbeat"))
			}
		}
	}
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	err = conn.acquireStream()
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		conn.releaseStream(false)
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		parent:      conn,
		destination: destination,
		keepSession: qtls.KeepSessionFromContext(ctx),
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	var sessionID uint16
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, c.udpStream, false, func() {
		conn.releaseUDPSession(sessionID)
	})
	conn.access.Lock()
	select {
	case <-conn.connDone:
		conn.access.Unlock()
		return nil, E.Errors(conn.connErr, os.ErrClosed)
	default:
	}
	sessionID = conn.udpSessionID
	conn.udpSessionID++
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.access.Unlock()
	clientPacketConn.sessionID = sessionID
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	c.connAccess.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	if pending != nil {
		pending.discarded = true
		pending.cause = err
	}
	c.connAccess.Unlock()

	if pending != nil {
		pending.cancel(err)
	}
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.closeIdle.Store(!keep)
	if !keep {
		c.CloseIdleConnections()
	}
}

func (c *Client) CloseIdleConnections() {
	c.connAccess.Lock()
	conn := c.conn
	c.connAccess.Unlock()
	if conn == nil {
		return
	}
	conn.access.Lock()
	drained := conn.streams == 0 && len(conn.udpConnMap) == 0
	conn.access.Unlock()
	if drained {
		conn.closeWithError(os.ErrClosed)
	}
}

type clientOffer struct {
	done      chan struct{}
	cancel    func(error)
	conn      *clientQUICConnection
	err       error
	discarded bool
	cause     error
}

type clientQUICConnection struct {
	quicConn     *quic.Conn
	rawConn      io.Closer
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	access       sync.RWMutex
	udpConnMap   map[uint16]*udpPacketConn
	udpSessionID uint16
	streams      int
	closeIdle    *atomic.Bool
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

func (c *clientQUICConnection) acquireStream() error {
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.connDone:
		return E.Errors(c.connErr, os.ErrClosed)
	default:
	}
	c.streams++
	return nil
}

func (c *clientQUICConnection) releaseStream(keepSession bool) {
	c.access.Lock()
	c.streams--
	drained := c.closeIdle.Load() && !keepSession && c.streams == 0 && len(c.udpConnMap) == 0
	c.access.Unlock()
	if drained {
		c.closeWithError(os.ErrClosed)
	}
}

func (c *clientQUICConnection) releaseUDPSession(sessionID uint16) {
	c.access.Lock()
	delete(c.udpConnMap, sessionID)
	drained := c.closeIdle.Load() && c.streams == 0 && len(c.udpConnMap) == 0
	c.access.Unlock()
	if drained {
		c.closeWithError(os.ErrClosed)
	}
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		c.access.Lock()
		close(c.connDone)
		udpConnMap := c.udpConnMap
		c.udpConnMap = make(map[uint16]*udpPacketConn)
		c.access.Unlock()
		for _, udpConn := range udpConnMap {
			udpConn.closeWithError(err)
		}
		_ = c.quicConn.CloseWithError(0, "")
		_ = c.rawConn.Close()
	})
}

type clientConn struct {
	*quic.Stream
	parent         *clientQUICConnection
	destination    M.Socksaddr
	keepSession    bool
	requestWritten bool
	closeOnce      sync.Once
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(b []byte) (n int, err error) {
	n, err = c.Stream.Read(b)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	if !c.requestWritten {
		request := buf.NewSize(2 + AddressSerializer.AddrPortLen(c.destination) + len(b))
		defer request.Release()
		request.WriteByte(Version)
		request.WriteByte(CommandConnect)
		err = AddressSerializer.WriteAddrPort(request, c.destination)
		if err != nil {
			return
		}
		request.Write(b)
		_, err = c.Stream.Write(request.Bytes())
		if err != nil {
			c.parent.closeWithError(E.Cause(err, "create new connection"))
			return 0, qtls.WrapError(err)
		}
		c.requestWritten = true
		return len(b), nil
	}
	n, err = c.Stream.Write(b)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	c.Stream.SetWriteDeadline(time.Now())
	c.closeOnce.Do(func() { c.parent.releaseStream(c.keepSession) })
	return err
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.destination
}
