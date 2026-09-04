package hysteria2

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing-quic/hysteria2/realm"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

const defaultHandshakeTimeout = 15 * time.Second

type ClientOptions struct {
	Context            context.Context
	Dialer             N.Dialer
	Logger             logger.Logger
	BrutalDebug        bool
	ServerAddress      M.Socksaddr
	ServerPorts        []string
	HopInterval        time.Duration
	HopIntervalMax     time.Duration
	SendBPS            uint64
	ReceiveBPS         uint64
	SalamanderPassword string
	GeckoPassword      string
	GeckoMinPacketSize int
	GeckoMaxPacketSize int
	Password           string
	TLSConfig          aTLS.Config
	QUICOptions        qtls.QUICOptions
	UDPDisabled        bool
	BBRProfile         string
	ChromeParrot       bool
	RealmOptions       *realm.Options
}

type Client struct {
	ctx                context.Context
	dialer             N.Dialer
	logger             logger.Logger
	brutalDebug        bool
	serverAddr         M.Socksaddr
	serverPorts        []uint16
	hopInterval        time.Duration
	hopIntervalMax     time.Duration
	sendBPS            uint64
	receiveBPS         uint64
	salamanderPassword string
	geckoPassword      string
	geckoMinPacketSize int
	geckoMaxPacketSize int
	password           string
	tlsConfig          aTLS.Config
	quicConfig         *quic.Config
	udpDisabled        bool
	bbrProfile         congestion_meta2.Profile
	realmOptions       *realm.Options
	controlClient      *realm.ControlClient

	connAccess sync.Mutex
	conn       *clientQUICConnection
	closeIdle  atomic.Bool
	pending    *clientOffer
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
		ChromeParrot:                   options.ChromeParrot,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	bbrProfile := congestion_meta2.ProfileStandard
	if options.BBRProfile != "" {
		var err error
		bbrProfile, err = congestion_meta2.ParseProfile(options.BBRProfile)
		if err != nil {
			return nil, err
		}
	}
	if options.RealmOptions != nil {
		if len(options.ServerPorts) > 0 {
			return nil, E.New("realm and port hopping are mutually exclusive")
		}
		if options.RealmOptions.IPVersion != 0 && options.RealmOptions.IPVersion != 4 && options.RealmOptions.IPVersion != 6 {
			return nil, E.New("invalid IP version: ", options.RealmOptions.IPVersion)
		}
		if options.RealmOptions.IPVersion == 6 && options.RealmOptions.PortMapping != nil {
			return nil, E.New("port mapping requires IPv4")
		}
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
	var controlClient *realm.ControlClient
	if options.RealmOptions != nil {
		var err error
		controlClient, err = realm.NewControlClient(options.RealmOptions.ServerURL, options.RealmOptions.Token, options.RealmOptions.HTTPClient)
		if err != nil {
			return nil, E.Cause(err, "create control client")
		}
	}
	var serverPorts []uint16
	if len(options.ServerPorts) > 0 {
		var err error
		serverPorts, err = hysteria.ParsePorts(options.ServerPorts)
		if err != nil {
			return nil, err
		}
	}
	return &Client{
		ctx:                options.Context,
		dialer:             options.Dialer,
		logger:             options.Logger,
		brutalDebug:        options.BrutalDebug,
		serverAddr:         options.ServerAddress,
		serverPorts:        serverPorts,
		hopInterval:        options.HopInterval,
		hopIntervalMax:     options.HopIntervalMax,
		sendBPS:            options.SendBPS,
		receiveBPS:         options.ReceiveBPS,
		salamanderPassword: options.SalamanderPassword,
		geckoPassword:      options.GeckoPassword,
		geckoMinPacketSize: options.GeckoMinPacketSize,
		geckoMaxPacketSize: options.GeckoMaxPacketSize,
		password:           options.Password,
		tlsConfig:          options.TLSConfig,
		quicConfig:         quicConfig,
		udpDisabled:        options.UDPDisabled,
		bbrProfile:         bbrProfile,
		realmOptions:       options.RealmOptions,
		controlClient:      controlClient,
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
	if c.realmOptions != nil {
		return c.offerNewRealm(ctx)
	}
	dialCtx := ctx
	hopCtx := c.ctx
	if hopCtx == nil {
		hopCtx = context.Background()
	}
	firstDial := true
	dialFunc := func(serverAddr M.Socksaddr) (net.Conn, error) {
		currentCtx := hopCtx
		if firstDial {
			// The initial socket open belongs to the shared offer. Later port hops
			// belong to the live client connection and must outlive any one caller.
			currentCtx = dialCtx
			firstDial = false
		}
		udpConn, err := c.dialer.DialContext(currentCtx, "udp", serverAddr)
		if err != nil {
			return nil, err
		}
		if c.geckoPassword == "" && c.salamanderPassword == "" {
			return udpConn, nil
		}
		if c.geckoPassword != "" {
			return NewGeckoClientConn(udpConn, []byte(c.geckoPassword), c.geckoMinPacketSize, c.geckoMaxPacketSize), nil
		}
		return NewSalamanderClientConn(udpConn, []byte(c.salamanderPassword)), nil
	}
	var (
		rawConn net.Conn
		err     error
	)
	if len(c.serverPorts) == 0 {
		rawConn, err = dialFunc(c.serverAddr)
		if err != nil {
			return nil, err
		}
		if c.geckoPassword != "" || c.salamanderPassword != "" {
			qtls.SetDesiredBufferSizes(rawConn)
		}
	} else {
		rawConn, err = hysteria.NewHopConn(dialFunc, c.serverAddr, c.serverPorts, c.hopInterval, c.hopIntervalMax)
		if err != nil {
			return nil, err
		}
	}
	return c.authenticateAndWrap(ctx, rawConn, func(quicConnPtr **quic.Conn) (http.RoundTripper, error) {
		return qtls.CreateTransport(rawConn, quicConnPtr, c.tlsConfig, c.quicConfig)
	})
}

type realmFamilyConn struct {
	family         string
	ipv4           bool
	conn           net.PacketConn
	localAddresses []netip.AddrPort
}

func (c *Client) offerNewRealm(ctx context.Context) (*clientQUICConnection, error) {
	families, err := c.realmOpenFamilies(ctx)
	if err != nil {
		return nil, err
	}
	var (
		portMapper   *realm.PortMapper
		mappedFamily *realmFamilyConn
	)
	if c.realmOptions.PortMapping != nil {
		for _, family := range families {
			if !family.ipv4 {
				continue
			}
			// The mapping is established before STUN discovery: with the pinhole
			// in place, in a double-NAT setup, the address STUN observes
			// corresponds to a path whose inner leg goes through the static
			// mapping rather than a filtered dynamic one.
			mapper, mapErr := realm.NewPortMapper(ctx, c.logger, M.SocksaddrFromNet(family.conn.LocalAddr()).Port, *c.realmOptions.PortMapping)
			if mapErr != nil {
				c.logger.Warn(E.Cause(mapErr, "port mapping unavailable; continuing without it"))
			} else {
				portMapper = mapper
				mappedFamily = family
			}
			break
		}
	}
	mapperAdopted := false
	if portMapper != nil {
		defer func() {
			if !mapperAdopted {
				_ = portMapper.Close()
			}
		}()
	}
	surviving, localAddresses, err := c.realmDiscoverFamilies(ctx, families)
	if err != nil {
		return nil, err
	}
	if portMapper != nil && slices.Contains(surviving, mappedFamily) {
		externalAddr := portMapper.ExternalAddr()
		if !slices.Contains(localAddresses, externalAddr) {
			localAddresses = append(localAddresses, externalAddr)
		}
	}
	closeSurviving := func() {
		for _, family := range surviving {
			_ = family.conn.Close()
		}
	}
	localMetadata, err := realm.GeneratePunchMetadata()
	if err != nil {
		closeSurviving()
		return nil, E.Cause(err, "generate punch metadata")
	}
	response, err := c.controlClient.Connect(ctx, c.realmOptions.RealmID, localAddresses, localMetadata)
	if err != nil {
		closeSurviving()
		return nil, E.Cause(err, "realm connect")
	}
	winner, result, err := c.realmRacePunch(ctx, surviving, response.Addresses, response.PunchMetadata)
	if err != nil {
		return nil, err
	}
	packetConn := winner.conn
	if c.geckoPassword != "" || c.salamanderPassword != "" {
		qtls.SetDesiredBufferSizes(packetConn)
	}
	if c.geckoPassword != "" {
		packetConn = NewGeckoConn(packetConn, []byte(c.geckoPassword), c.geckoMinPacketSize, c.geckoMaxPacketSize)
	} else if c.salamanderPassword != "" {
		packetConn = NewSalamanderConn(packetConn, []byte(c.salamanderPassword))
	}
	peerAddr := M.SocksaddrFromNetIP(result.PeerAddr)
	conn, err := c.authenticateAndWrap(ctx, packetConn, func(quicConnPtr **quic.Conn) (http.RoundTripper, error) {
		return qtls.CreatePacketTransport(packetConn, peerAddr.UDPAddr(), quicConnPtr, c.tlsConfig, c.quicConfig)
	})
	if err != nil {
		return nil, err
	}
	if winner == mappedFamily {
		mapperAdopted = true
		go portMapper.KeepAlive(conn.connDone)
	}
	return conn, nil
}

func (c *Client) realmOpenFamilies(ctx context.Context) ([]*realmFamilyConn, error) {
	specs := []struct {
		family string
		ipv4   bool
		addr   M.Socksaddr
	}{
		{"v4", true, M.SocksaddrFrom(netip.IPv4Unspecified(), 0)},
		{"v6", false, M.SocksaddrFrom(netip.IPv6Unspecified(), 0)},
	}
	switch c.realmOptions.IPVersion {
	case 4:
		specs = specs[:1]
	case 6:
		specs = specs[1:]
	}
	conns := make([]*realmFamilyConn, len(specs))
	listenErrs := make([]error, len(specs))
	var wg sync.WaitGroup
	for i, spec := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, listenErr := c.dialer.ListenPacket(ctx, spec.addr)
			if listenErr != nil {
				listenErrs[i] = E.Cause(listenErr, spec.family)
				return
			}
			conns[i] = &realmFamilyConn{family: spec.family, ipv4: spec.ipv4, conn: conn}
		}()
	}
	wg.Wait()
	var families []*realmFamilyConn
	var errs []error
	for i, family := range conns {
		if family != nil {
			families = append(families, family)
			continue
		}
		errs = append(errs, listenErrs[i])
	}
	if len(families) == 0 {
		return nil, E.Cause(E.Errors(errs...), "listen UDP for realm")
	}
	return families, nil
}

func (c *Client) realmDiscoverFamilies(ctx context.Context, families []*realmFamilyConn) ([]*realmFamilyConn, []netip.AddrPort, error) {
	var needIPv4, needIPv6 bool
	for _, family := range families {
		if family.ipv4 {
			needIPv4 = true
		} else {
			needIPv6 = true
		}
	}
	stunServers, err := realm.ResolveSTUNServers(ctx, c.realmOptions.STUNServers, c.realmOptions.Resolver, needIPv4, needIPv6)
	if err != nil {
		for _, family := range families {
			_ = family.conn.Close()
		}
		return nil, nil, E.Cause(err, "resolve STUN servers")
	}
	type discoverResult struct {
		addrs []netip.AddrPort
		err   error
	}
	results := make([]discoverResult, len(families))
	var wg sync.WaitGroup
	for i, family := range families {
		wg.Add(1)
		go func() {
			defer wg.Done()
			servers := make([]netip.AddrPort, 0, len(stunServers))
			for _, server := range stunServers {
				if server.Addr().Is4() == family.ipv4 {
					servers = append(servers, server)
				}
			}
			addrs, discoverErr := realm.Discover(ctx, family.conn, servers)
			results[i] = discoverResult{addrs: addrs, err: discoverErr}
		}()
	}
	wg.Wait()
	var surviving []*realmFamilyConn
	var union []netip.AddrPort
	var errs []error
	for i, family := range families {
		result := results[i]
		if result.err != nil {
			errs = append(errs, E.Cause(result.err, family.family))
			_ = family.conn.Close()
			continue
		}
		family.localAddresses = result.addrs
		surviving = append(surviving, family)
		union = append(union, result.addrs...)
	}
	if len(surviving) == 0 {
		return nil, nil, E.Cause(E.Errors(errs...), "realm STUN discovery")
	}
	return surviving, union, nil
}

func (c *Client) realmRacePunch(
	ctx context.Context,
	families []*realmFamilyConn,
	peerAddresses []netip.AddrPort,
	metadata realm.PunchMetadata,
) (*realmFamilyConn, realm.PunchResult, error) {
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()
	type outcome struct {
		family *realmFamilyConn
		result realm.PunchResult
		err    error
	}
	out := make(chan outcome, len(families))
	for _, family := range families {
		go func() {
			peers := make([]netip.AddrPort, 0, len(peerAddresses))
			for _, peer := range peerAddresses {
				if peer.Addr().Is4() == family.ipv4 {
					peers = append(peers, peer)
				}
			}
			punchResult, punchErr := realm.Punch(raceCtx, family.conn, peers, metadata)
			out <- outcome{family: family, result: punchResult, err: punchErr}
		}()
	}
	var errs []error
	for pending := len(families); pending > 0; pending-- {
		result := <-out
		if result.err == nil {
			for _, family := range families {
				if family != result.family {
					_ = family.conn.Close()
				}
			}
			return result.family, result.result, nil
		}
		errs = append(errs, E.Cause(result.err, result.family.family))
	}
	for _, family := range families {
		_ = family.conn.Close()
	}
	return nil, realm.PunchResult{}, E.Cause(E.Errors(errs...), "realm punch")
}

func (c *Client) authenticateAndWrap(ctx context.Context, rawConn io.Closer, createTransport func(quicConnPtr **quic.Conn) (http.RoundTripper, error)) (*clientQUICConnection, error) {
	var quicConn *quic.Conn
	http3Transport, err := createTransport(&quicConn)
	if err != nil {
		rawConn.Close()
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
	handshakeTimeout := c.tlsConfig.HandshakeTimeout()
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	authCtx, authCancel := context.WithTimeout(ctx, handshakeTimeout)
	defer authCancel()
	response, err := http3Transport.RoundTrip(request.WithContext(authCtx))
	if err != nil {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		rawConn.Close()
		return nil, err
	}
	response.Body.Close()
	if response.StatusCode != protocol.StatusAuthOK {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		rawConn.Close()
		return nil, E.New("authentication failed, status code: ", response.StatusCode)
	}
	authResponse := protocol.AuthResponseFromHeader(response.Header)
	actualTx := authResponse.Rx
	if actualTx == 0 || actualTx > c.sendBPS {
		actualTx = c.sendBPS
	}
	if !authResponse.RxAuto && actualTx > 0 {
		quicConn.SetCongestionControl(hyCC.NewBrutalSender(actualTx, quicConn.InitialPacketSize(), c.brutalDebug, c.logger))
	} else {
		quicConn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(
			quicConn.InitialPacketSize(),
			c.bbrProfile,
		))
	}
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     rawConn,
		connDone:    make(chan struct{}),
		udpDisabled: !authResponse.UDPEnabled,
		udpConnMap:  make(map[uint32]*udpPacketConn),
		closeIdle:   &c.closeIdle,
	}
	if !c.udpDisabled {
		go c.loopMessages(conn)
	}
	go func() {
		<-quicConn.Context().Done()
		conn.closeWithError(context.Cause(quicConn.Context()))
	}()
	return conn, nil
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
	udpDisabled  bool
	access       sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32
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

func (c *clientQUICConnection) releaseUDPSession(sessionID uint32) {
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
		c.udpConnMap = make(map[uint32]*udpPacketConn)
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
	responseRead   bool
	closeOnce      sync.Once
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.responseRead {
		n, err = c.Stream.Read(p)
		return n, qtls.WrapError(err)
	}
	status, errorMessage, err := protocol.ReadTCPResponse(c.Stream)
	if err != nil {
		return 0, qtls.WrapError(err)
	}
	if !status {
		err = E.New("remote error: ", errorMessage)
		return
	}
	c.responseRead = true
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		buffer := protocol.WriteTCPRequest(c.destination.String(), p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return
		}
		c.requestWritten = true
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
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
