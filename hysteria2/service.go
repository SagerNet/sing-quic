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
	userMap               map[string]U
	udpDisabled           bool
	udpTimeout            time.Duration
	handler               ServerHandler
	masqueradeHandler     http.Handler
	quicListener          io.Closer
	bbrProfile            congestion_meta2.Profile
	realmServer           *realm.Server

	sessionAccess sync.Mutex
	sessions      map[*serverSession[U]]struct{}
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
		userMap:               make(map[string]U),
		udpDisabled:           options.UDPDisabled,
		udpTimeout:            options.UDPTimeout,
		handler:               options.Handler,
		masqueradeHandler:     options.MasqueradeHandler,
		bbrProfile:            bbrProfile,
		realmServer:           realmServer,
		sessions:              make(map[*serverSession[U]]struct{}),
	}, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[string]U)
	for i, user := range userList {
		userMap[passwordList[i]] = user
	}
	s.userMap = userMap
	s.closeRemovedSessions(userList)
}

// trackSession registers an authenticated session, so that a later UpdateUsers
// can revoke it. Only authenticated sessions are registered: before that there
// is no user to match a removed one against.
func (s *Service[U]) trackSession(session *serverSession[U]) {
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	s.sessions[session] = struct{}{}
}

func (s *Service[U]) untrackSession(session *serverSession[U]) {
	s.sessionAccess.Lock()
	defer s.sessionAccess.Unlock()
	delete(s.sessions, session)
}

// closeRemovedSessions closes the sessions of users that are gone from the new
// user table. A session authenticates once and then multiplexes every later
// stream over the same QUIC connection without consulting the user table
// again, so dropping a user from it does not by itself revoke the access that
// user already has.
//
// Victims are collected under the lock and closed after it is released, so
// that the close path is never run with the session lock held.
func (s *Service[U]) closeRemovedSessions(userList []U) {
	users := make(map[U]struct{}, len(userList))
	for _, user := range userList {
		users[user] = struct{}{}
	}
	s.sessionAccess.Lock()
	var removed []*serverSession[U]
	for session := range s.sessions {
		if _, stillValid := users[session.authUser]; !stillValid {
			removed = append(removed, session)
		}
	}
	s.sessionAccess.Unlock()
	for _, session := range removed {
		session.closeWithError(E.New("user removed"))
	}
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	if s.realmServer != nil {
		return s.startWithRealm(conn)
	}
	if s.geckoPassword != "" {
		conn = NewGeckoConn(conn, []byte(s.geckoPassword), s.geckoMinPacketSize, s.geckoMaxPacketSize)
	} else if s.salamanderPassword != "" {
		conn = NewSalamanderConn(conn, []byte(s.salamanderPassword))
	}
	err := qtls.ConfigureHTTP3(s.tlsConfig)
	if err != nil {
		return err
	}
	obfsEnabled := s.geckoPassword != "" || s.salamanderPassword != ""
	listener, err := qtls.ListenWithOptions(conn, s.tlsConfig, s.quicConfig, qtls.ListenOptions{
		DisableVersionNegotiationPackets: obfsEnabled,
		StatelessReset:                   !obfsEnabled,
	})
	if err != nil {
		return err
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *Service[U]) startWithRealm(conn net.PacketConn) error {
	punchConn, err := s.realmServer.Start(s.ctx, conn)
	if err != nil {
		return E.Cause(err, "start realm server")
	}
	var quicConn net.PacketConn = punchConn
	if s.geckoPassword != "" {
		quicConn = NewGeckoConn(quicConn, []byte(s.geckoPassword), s.geckoMinPacketSize, s.geckoMaxPacketSize)
	} else if s.salamanderPassword != "" {
		quicConn = NewSalamanderConn(quicConn, []byte(s.salamanderPassword))
	}
	err = qtls.ConfigureHTTP3(s.tlsConfig)
	if err != nil {
		return E.Errors(err, s.realmServer.Close())
	}
	obfsEnabled := s.geckoPassword != "" || s.salamanderPassword != ""
	listener, err := qtls.ListenWithOptions(quicConn, s.tlsConfig, s.quicConfig, qtls.ListenOptions{
		DisableVersionNegotiationPackets: obfsEnabled,
		StatelessReset:                   !obfsEnabled,
	})
	if err != nil {
		return E.Errors(err, s.realmServer.Close())
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
	session := &serverSession[U]{
		Service:    s,
		ctx:        s.ctx,
		quicConn:   connection,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	defer s.untrackSession(session)
	httpServer := http3.Server{
		Handler:          session,
		StreamDispatcher: session.dispatchStream,
	}
	_ = httpServer.ServeQUICConn(connection)
	_ = connection.CloseWithError(0, "")
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx           context.Context
	quicConn      *quic.Conn
	connAccess    sync.Mutex
	connDone      chan struct{}
	connErr       error
	authenticated bool
	authUser      U
	udpAccess     sync.RWMutex
	udpConnMap    map[uint32]*udpPacketConn
}

func (s *serverSession[U]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		if s.authenticated {
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !s.udpDisabled,
				Rx:         s.receiveBPS,
				RxAuto:     s.receiveBPS == 0 && s.ignoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		request := protocol.AuthRequestFromHeader(r.Header)
		user, loaded := s.userMap[request.Auth]
		if !loaded {
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		}
		s.authUser = user
		s.authenticated = true
		s.trackSession(s)
		var rxAuto bool
		if s.receiveBPS > 0 && s.ignoreClientBandwidth && request.Rx == 0 {
			s.logger.Debug("process connection from ", r.RemoteAddr, ": BBR disabled by server")
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		} else if !(s.receiveBPS == 0 && s.ignoreClientBandwidth) && request.Rx > 0 {
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
		if s.ctx.Done() != nil {
			go func() {
				select {
				case <-s.ctx.Done():
					s.closeWithError(s.ctx.Err())
				case <-s.connDone:
				}
			}()
		}
		if !s.udpDisabled {
			go s.loopMessages()
		}
	} else {
		s.masqueradeHandler.ServeHTTP(w, r)
	}
}

func (s *serverSession[U]) dispatchStream(frameType http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if !s.authenticated || err != nil {
		return false, nil
	}
	if frameType != protocol.FrameTypeTCPRequest {
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
	s.handler.NewConnectionEx(auth.ContextWithUser(s.ctx, s.authUser), &serverConn{Stream: stream}, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), M.ParseSocksaddr(destinationString).Unwrap(), nil)
	return nil
}

func (s *serverSession[U]) closeWithError(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	if E.IsClosedOrCanceled(err) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint32]*udpPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
	_ = s.quicConn.CloseWithError(0, "")
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
