package hysteria2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ServiceOptions struct {
	Context               context.Context
	Logger                logger.Logger
	BrutalDebug           bool
	SendBPS               uint64
	ReceiveBPS            uint64
	IgnoreClientBandwidth bool
	SalamanderPassword    string
	GeckoPassword         string
	GeckoMinPacketSize    int
	GeckoMaxPacketSize    int
	TLSConfig             aTLS.ServerConfig
	QUICOptions           qtls.QUICOptions
	UDPDisabled           bool
	UDPTimeout            time.Duration
	Handler               ServerHandler
	MasqueradeHandler     http.Handler
	BBRProfile            string
	RealmOptions          *realm.Options
}

type ServerHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Service[U comparable] struct {
	ctx                   context.Context
	logger                logger.Logger
	brutalDebug           bool
	sendBPS               uint64
	receiveBPS            uint64
	ignoreClientBandwidth bool
	salamanderPassword    string
	geckoPassword         string
	geckoMinPacketSize    int
	geckoMaxPacketSize    int
	tlsConfig             aTLS.ServerConfig
	quicConfig            *quic.Config
	usersMu               sync.RWMutex
	userMap               map[string]U
	sessions              map[*serverSession[U]]string
	udpDisabled           bool
	udpTimeout            time.Duration
	handler               ServerHandler
	masqueradeHandler     http.Handler
	quicListener          io.Closer
	bbrProfile            congestion_meta2.Profile
	realmServer           *realm.Server
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                !options.UDPDisabled,
		MaxIncomingStreams:             1 << 60,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
		DisablePathManager:             true,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	bbrProfile := congestion_meta2.ProfileStandard
	if options.BBRProfile != "" {
		var err error
		bbrProfile, err = congestion_meta2.ParseProfile(options.BBRProfile)
		if err != nil {
			return nil, err
		}
	}
	if options.MasqueradeHandler == nil {
		options.MasqueradeHandler = http.NotFoundHandler()
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	if options.GeckoPassword != "" {
		if options.GeckoMinPacketSize == 0 {
			options.GeckoMinPacketSize = geckoDefaultMinPacketSize
		}
		if options.GeckoMaxPacketSize == 0 {
			options.GeckoMaxPacketSize = geckoDefaultMaxPacketSize
		}
		if options.GeckoMinPacketSize <= 0 || options.GeckoMinPacketSize > options.GeckoMaxPacketSize || options.GeckoMaxPacketSize > geckoMaxOnWireSize {
			return nil, E.New("gecko: invalid packet size range")
		}
	}
	var realmServer *realm.Server
	if options.RealmOptions != nil {
		var err error
		realmServer, err = realm.NewServer(*options.RealmOptions)
		if err != nil {
			return nil, E.Cause(err, "create realm server")
		}
	}
	return &Service[U]{
		ctx:                   options.Context,
		logger:                options.Logger,
		brutalDebug:           options.BrutalDebug,
		sendBPS:               options.SendBPS,
		receiveBPS:            options.ReceiveBPS,
		ignoreClientBandwidth: options.IgnoreClientBandwidth,
		salamanderPassword:    options.SalamanderPassword,
		geckoPassword:         options.GeckoPassword,
		geckoMinPacketSize:    options.GeckoMinPacketSize,
		geckoMaxPacketSize:    options.GeckoMaxPacketSize,
		tlsConfig:             options.TLSConfig,
		quicConfig:            quicConfig,
		sessions:              make(map[*serverSession[U]]string),
		udpDisabled:           options.UDPDisabled,
		udpTimeout:            options.UDPTimeout,
		handler:               options.Handler,
		masqueradeHandler:     options.MasqueradeHandler,
		bbrProfile:            bbrProfile,
		realmServer:           realmServer,
	}, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[string]U)
	for i, user := range userList {
		userMap[passwordList[i]] = user
	}
	// Invalidate bindings before closing the transports. A later refresh must
	// never reauthorize a session whose credential or identity was removed.
	s.usersMu.Lock()
	s.userMap = userMap
	revoked := s.detachSessionsLocked(func(previous U, password string) bool {
		user, ok := userMap[password]
		return !ok || user != previous
	})
	s.usersMu.Unlock()
	for _, session := range revoked {
		session.close()
	}
}

// CloseUserSessions disconnects existing sessions. An authorized user can log in again.
func (s *Service[U]) CloseUserSessions(user U) {
	s.usersMu.Lock()
	revoked := s.detachSessionsLocked(func(previous U, _ string) bool { return previous == user })
	s.usersMu.Unlock()
	for _, session := range revoked {
		session.close()
	}
}

func (s *Service[U]) detachSessionsLocked(matches func(U, string) bool) []*serverSession[U] {
	var revoked []*serverSession[U]
	for session, password := range s.sessions {
		if matches(session.authUser, password) {
			session.closed = true
			delete(s.sessions, session)
			revoked = append(revoked, session)
		}
	}
	return revoked
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	err := qtls.ConfigureHTTP3(s.tlsConfig)
	if err != nil {
		return err
	}
	var options qtls.ListenOptions
	if s.geckoPassword != "" {
		options.PacketCodec = NewGeckoCodec([]byte(s.geckoPassword), s.geckoMinPacketSize, s.geckoMaxPacketSize)
	} else if s.salamanderPassword != "" {
		options.PacketCodec = NewSalamanderCodec([]byte(s.salamanderPassword))
	}
	options.DisableVersionNegotiationPackets = options.PacketCodec != nil
	options.StatelessReset = options.PacketCodec == nil
	if s.realmServer != nil {
		var punchConn *realm.PunchPacketConn
		punchConn, err = s.realmServer.Start(s.ctx, conn)
		if err != nil {
			return E.Cause(err, "start realm server")
		}
		options.PacketInterceptor = punchConn.InterceptPacket
	}
	listener, err := qtls.ListenWithOptions(conn, s.tlsConfig, s.quicConfig, options)
	if err != nil {
		if s.realmServer != nil {
			return E.Errors(err, s.realmServer.Close())
		}
		return err
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *Service[U]) Close() error {
	var realmErr error
	if s.realmServer != nil {
		realmErr = s.realmServer.Close()
	}
	return E.Errors(realmErr, common.Close(s.quicListener))
}

func (s *Service[U]) Reset() {
	if s.realmServer != nil {
		s.realmServer.Reset()
	}
}

func (s *Service[U]) loopConnections(listener qtls.Listener) {
	for {
		connection, err := listener.Accept(s.ctx)
		if err != nil {
			if E.IsClosedOrCanceled(err) || errors.Is(err, quic.ErrServerClosed) {
				s.logger.Debug(E.Cause(err, "listener closed"))
			} else {
				s.logger.Error(E.Cause(err, "listener closed"))
			}
			return
		}
		go s.handleConnection(connection)
	}
}

func (s *Service[U]) handleConnection(connection *quic.Conn) {
	ctx, cancel := context.WithCancel(s.ctx)
	session := &serverSession[U]{
		Service:    s,
		ctx:        ctx,
		cancel:     cancel,
		quicConn:   connection,
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	stop := context.AfterFunc(s.ctx, session.close)
	defer stop()
	defer session.close()
	httpServer := http3.Server{
		Handler:          session,
		StreamDispatcher: session.dispatchStream,
	}
	_ = httpServer.ServeQUICConn(connection)
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx        context.Context
	quicConn   *quic.Conn
	cancel     context.CancelFunc
	closeOnce  sync.Once
	closed     bool // protected by usersMu
	authUser   U    // immutable after registration under usersMu
	udpAccess  sync.RWMutex
	udpConnMap map[uint32]*udpPacketConn
}

// authorize makes credential lookup and session registration atomic with UpdateUsers.
func (s *serverSession[U]) authorize(password string, allowNew bool) (ok, first bool) {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return false, false
	}
	if _, active := s.sessions[s]; active {
		return true, false
	}
	user, valid := s.userMap[password]
	if !valid || !allowNew {
		return false, false
	}
	s.authUser = user
	s.sessions[s] = password
	return true, true
}

func (s *serverSession[U]) active() bool {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	_, ok := s.sessions[s]
	return ok
}

func (s *serverSession[U]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		request := protocol.AuthRequestFromHeader(r.Header)
		allowNew := !(s.receiveBPS > 0 && s.ignoreClientBandwidth && request.Rx == 0)
		ok, first := s.authorize(request.Auth, allowNew)
		if !ok {
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		}
		if !first {
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !s.udpDisabled,
				Rx:         s.receiveBPS,
				RxAuto:     s.receiveBPS == 0 && s.ignoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		var rxAuto bool
		if !(s.receiveBPS == 0 && s.ignoreClientBandwidth) && request.Rx > 0 {
			rx := request.Rx
			if s.sendBPS > 0 && rx > s.sendBPS {
				rx = s.sendBPS
			}
			s.quicConn.SetCongestionControl(hyCC.NewBrutalSender(rx, s.quicConn.InitialPacketSize(), s.brutalDebug, s.logger))
		} else {
			s.quicConn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(
				s.quicConn.InitialPacketSize(),
				s.bbrProfile,
			))
			rxAuto = true
		}
		protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
			UDPEnabled: !s.udpDisabled,
			Rx:         s.receiveBPS,
			RxAuto:     rxAuto,
		})
		w.WriteHeader(protocol.StatusAuthOK)
		if !s.udpDisabled {
			go s.loopMessages()
		}
	} else {
		s.masqueradeHandler.ServeHTTP(w, r)
	}
}

func (s *serverSession[U]) dispatchStream(frameType http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if err != nil || frameType != protocol.FrameTypeTCPRequest || !s.active() {
		return false, nil
	}
	_, err = quicvarint.Read(quicvarint.NewReader(stream))
	if err != nil {
		s.logger.Error(E.Cause(err, "seek frame type"))
		return true, nil
	}
	go func() {
		hErr := s.handleStream(stream)
		if hErr != nil {
			stream.CancelRead(0)
			stream.Close()
			s.logger.Error(E.Cause(hErr, "handle stream request"))
		}
	}()
	return true, nil
}

func (s *serverSession[U]) handleStream(stream *quic.Stream) error {
	destinationString, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		return E.New("read TCP request")
	}
	destination := M.ParseSocksaddr(destinationString).Unwrap()
	if len(destination.Fqdn) > 255 {
		return E.New("fqdn too long")
	}
	if !s.active() {
		return net.ErrClosed
	}
	s.handler.NewConnectionEx(auth.ContextWithUser(s.ctx, s.authUser), &serverConn{Stream: stream}, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), destination, nil)
	return nil
}

func (s *serverSession[U]) closeWithError(err error) {
	s.closeWithCause(err)
	if E.IsClosedOrCanceled(err) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
}

func (s *serverSession[U]) close() {
	s.closeWithCause(net.ErrClosed)
}

func (s *serverSession[U]) closeWithCause(err error) {
	s.closeOnce.Do(func() {
		s.usersMu.Lock()
		s.closed = true
		delete(s.sessions, s)
		s.usersMu.Unlock()
		s.cancel()
		s.udpAccess.Lock()
		udpConnMap := s.udpConnMap
		s.udpConnMap = make(map[uint32]*udpPacketConn)
		s.udpAccess.Unlock()
		for _, udpConn := range udpConnMap {
			udpConn.closeWithError(err)
		}
		_ = s.quicConn.CloseWithError(0, "")
	})
}

type serverConn struct {
	*quic.Stream
	responseWritten bool
}

func (c *serverConn) HandshakeFailure(err error) error {
	if c.responseWritten {
		return os.ErrInvalid
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(false, err.Error(), nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) HandshakeSuccess() error {
	if c.responseWritten {
		return nil
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(true, "", nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	if !c.responseWritten {
		c.responseWritten = true
		buffer := protocol.WriteTCPResponse(true, "", p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return 0, qtls.WrapError(err)
		}
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	c.Stream.SetWriteDeadline(time.Now())
	return err
}
