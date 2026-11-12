package qtls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type QUICOptions struct {
	IdleTimeout             time.Duration
	KeepAlivePeriod         time.Duration
	StreamReceiveWindow     uint64
	ConnectionReceiveWindow uint64
	MaxConcurrentStreams    int
	InitialPacketSize       int
	// InitialPacketSizeCeiling is the largest UDP payload this connection may put
	// on the wire, when the caller has PROVED the path cannot carry more.
	//
	// It is separate from InitialPacketSize because the two are different kinds of
	// statement: InitialPacketSize is a preference the QUIC implementation may
	// legitimately replace (ChromeParrot pins a fingerprint size), while a ceiling
	// describes the tunnel underneath and must survive every replacement.
	//
	// 0 means no ceiling. The value is passed through unchanged - in particular it
	// is NOT raised to the QUIC minimum. A path that cannot carry a 1200-byte
	// Initial packet cannot carry a QUIC handshake at all, and the caller that
	// established that is the one that has to refuse the configuration, with a
	// message naming the tunnel. Raising it here would send a packet the caller
	// proved the path drops, and the failure would surface far from its cause.
	InitialPacketSizeCeiling int
	DisablePathMTUDiscovery  bool
}

type Config interface {
	Dial(ctx context.Context, conn net.Conn, config *quic.Config) (*quic.Conn, error)
	DialEarly(ctx context.Context, conn net.Conn, config *quic.Config) (*quic.Conn, error)
	CreateTransport(conn net.Conn, quicConnPtr **quic.Conn, quicConfig *quic.Config) http.RoundTripper
	CreatePacketTransport(conn net.PacketConn, remoteAddr net.Addr, quicConnPtr **quic.Conn, quicConfig *quic.Config) http.RoundTripper
}

type ServerConfig interface {
	Listen(conn net.PacketConn, config *quic.Config) (Listener, error)
	ListenEarly(conn net.PacketConn, config *quic.Config) (EarlyListener, error)
	ConfigureHTTP3()
}

type Listener interface {
	Accept(ctx context.Context) (*quic.Conn, error)
	Close() error
	Addr() net.Addr
}

type EarlyListener interface {
	Accept(ctx context.Context) (*quic.Conn, error)
	Close() error
	Addr() net.Addr
}

func ApplyQUICOptions(quicConfig *quic.Config, options QUICOptions) {
	if options.StreamReceiveWindow != 0 {
		quicConfig.InitialStreamReceiveWindow = options.StreamReceiveWindow
		quicConfig.MaxStreamReceiveWindow = options.StreamReceiveWindow
	}
	if options.ConnectionReceiveWindow != 0 {
		quicConfig.InitialConnectionReceiveWindow = options.ConnectionReceiveWindow
		quicConfig.MaxConnectionReceiveWindow = options.ConnectionReceiveWindow
	}
	if options.MaxConcurrentStreams > 0 {
		quicConfig.MaxIncomingStreams = int64(options.MaxConcurrentStreams)
	}
	if options.KeepAlivePeriod > 0 {
		quicConfig.KeepAlivePeriod = options.KeepAlivePeriod
	}
	if options.IdleTimeout > 0 {
		quicConfig.MaxIdleTimeout = options.IdleTimeout
	}
	if options.InitialPacketSize > 0 {
		quicConfig.InitialPacketSize = uint16(options.InitialPacketSize)
	}
	if options.InitialPacketSizeCeiling > 0 {
		// Passed through as an integer and converted once, so a caller that
		// computed a value the field cannot hold sees it here rather than as a
		// silently truncated ceiling. The field is a uint16 in quic-go because a
		// UDP payload cannot exceed 65535 bytes; anything larger is a caller error,
		// and clamping it to the maximum is the conservative direction (a smaller
		// ceiling is never less safe than a larger one).
		if options.InitialPacketSizeCeiling > maxUint16 {
			quicConfig.InitialPacketSizeCeiling = maxUint16
		} else {
			quicConfig.InitialPacketSizeCeiling = uint16(options.InitialPacketSizeCeiling)
		}
	}
	if options.DisablePathMTUDiscovery {
		quicConfig.DisablePathMTUDiscovery = true
	}
}

// maxUint16 is the largest value quic.Config.InitialPacketSizeCeiling can hold.
const maxUint16 = 1<<16 - 1

func SetDesiredBufferSizes(conn any) {
	// quic-go's internal protocol.DesiredReceiveBufferSize and protocol.DesiredSendBufferSize.
	const desiredUDPBufferSize = 8 << 20
	readCapable, canSetReadBuffer := common.Cast[interface {
		SetReadBuffer(bytes int) error
	}](conn)
	if canSetReadBuffer {
		_ = readCapable.SetReadBuffer(desiredUDPBufferSize)
	}
	writeCapable, canSetWriteBuffer := common.Cast[interface {
		SetWriteBuffer(bytes int) error
	}](conn)
	if canSetWriteBuffer {
		_ = writeCapable.SetWriteBuffer(desiredUDPBufferSize)
	}
}

var _ quic.IOActivityConn = (*syscallConn)(nil)

type syscallConn struct {
	net.Conn
	socket  syscall.Conn
	onRead  func(size int)
	onWrite func(size int)
}

func (c *syscallConn) SyscallConn() (syscall.RawConn, error) {
	return c.socket.SyscallConn()
}

func (c *syscallConn) IOActivityFuncs() (onRead func(size int), onWrite func(size int)) {
	return c.onRead, c.onWrite
}

func (c *syscallConn) Upstream() any {
	return c.Conn
}

func (c *syscallConn) ReaderReplaceable() bool {
	return true
}

func (c *syscallConn) WriterReplaceable() bool {
	return true
}

func withSyscallConn(conn net.Conn) net.Conn {
	reader, readCounters := N.UnwrapCountReader(conn, nil)
	socket, isSyscallConn := reader.(syscall.Conn)
	if !isSyscallConn {
		return conn
	}
	_, writeCounters := N.UnwrapCountWriter(conn, nil)
	return &syscallConn{
		Conn:    conn,
		socket:  socket,
		onRead:  activityFunc(readCounters),
		onWrite: activityFunc(writeCounters),
	}
}

func activityFunc(counters []N.CountFunc) func(size int) {
	if len(counters) == 0 {
		return nil
	}
	return func(size int) {
		for _, counter := range counters {
			counter(int64(size))
		}
	}
}

func quicConfigWithHandshakeTimeout(quicConfig *quic.Config, handshakeTimeout time.Duration) *quic.Config {
	if handshakeTimeout <= 0 {
		return quicConfig
	}
	if quicConfig == nil {
		return &quic.Config{HandshakeIdleTimeout: handshakeTimeout}
	}
	if quicConfig.HandshakeIdleTimeout != 0 {
		return quicConfig
	}
	quicConfig.HandshakeIdleTimeout = handshakeTimeout
	return quicConfig
}

func Dial(ctx context.Context, conn net.Conn, config aTLS.Config, quicConfig *quic.Config) (*quic.Conn, error) {
	conn = withSyscallConn(conn)
	quicConfig = quicConfigWithHandshakeTimeout(quicConfig, config.HandshakeTimeout())
	if quicTLSConfig, isQUICConfig := config.(Config); isQUICConfig {
		quicConn, err := quicTLSConfig.Dial(ctx, conn, quicConfig)
		return quicConn, WrapError(err)
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	quicConn, err := quic.DialConn(ctx, conn, tlsConfig, quicConfig)
	return quicConn, WrapError(err)
}

func DialEarly(ctx context.Context, conn net.Conn, config aTLS.Config, quicConfig *quic.Config) (*quic.Conn, error) {
	conn = withSyscallConn(conn)
	quicConfig = quicConfigWithHandshakeTimeout(quicConfig, config.HandshakeTimeout())
	if quicTLSConfig, isQUICConfig := config.(Config); isQUICConfig {
		quicConn, err := quicTLSConfig.DialEarly(ctx, conn, quicConfig)
		return quicConn, WrapError(err)
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	quicConn, err := quic.DialEarlyConn(ctx, conn, tlsConfig, quicConfig)
	return quicConn, WrapError(err)
}

func CreateTransport(conn net.Conn, quicConnPtr **quic.Conn, config aTLS.Config, quicConfig *quic.Config) (http.RoundTripper, error) {
	conn = withSyscallConn(conn)
	handshakeTimeout := config.HandshakeTimeout()
	quicConfig = quicConfigWithHandshakeTimeout(quicConfig, handshakeTimeout)
	if quicTLSConfig, isQUICConfig := config.(Config); isQUICConfig {
		return quicTLSConfig.CreateTransport(conn, quicConnPtr, quicConfig), nil
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	return &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			cfg = quicConfigWithHandshakeTimeout(cfg, handshakeTimeout)
			quicConn, err := quic.DialEarlyConn(ctx, conn, tlsCfg, cfg)
			if err != nil {
				return nil, WrapError(err)
			}
			*quicConnPtr = quicConn
			return quicConn, nil
		},
	}, nil
}

func CreatePacketTransport(conn net.PacketConn, remoteAddr net.Addr, quicConnPtr **quic.Conn, config aTLS.Config, quicConfig *quic.Config) (http.RoundTripper, error) {
	handshakeTimeout := config.HandshakeTimeout()
	quicConfig = quicConfigWithHandshakeTimeout(quicConfig, handshakeTimeout)
	if quicTLSConfig, isQUICConfig := config.(Config); isQUICConfig {
		return quicTLSConfig.CreatePacketTransport(conn, remoteAddr, quicConnPtr, quicConfig), nil
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	return &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			cfg = quicConfigWithHandshakeTimeout(cfg, handshakeTimeout)
			quicConn, err := quic.DialEarly(ctx, conn, remoteAddr, tlsCfg, cfg)
			if err != nil {
				return nil, WrapError(err)
			}
			*quicConnPtr = quicConn
			return quicConn, nil
		},
	}, nil
}

type ListenOptions struct {
	DisableVersionNegotiationPackets bool
	StatelessReset                   bool
}

func Listen(conn net.PacketConn, config aTLS.ServerConfig, quicConfig *quic.Config) (Listener, error) {
	return ListenWithOptions(conn, config, quicConfig, ListenOptions{})
}

func ListenWithOptions(conn net.PacketConn, config aTLS.ServerConfig, quicConfig *quic.Config, options ListenOptions) (Listener, error) {
	quicConfig = quicConfigWithHandshakeTimeout(quicConfig, config.HandshakeTimeout())
	if quicTLSConfig, isQUICConfig := config.(ServerConfig); isQUICConfig {
		listener, err := quicTLSConfig.Listen(conn, quicConfig)
		return listener, WrapError(err)
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	transport := quic.Transport{Conn: conn, DisableVersionNegotiationPackets: options.DisableVersionNegotiationPackets}
	transport.SetSingleUse(true)
	if options.StatelessReset {
		transport.StatelessResetKey = new(quic.StatelessResetKey)
		_, err = rand.Read(transport.StatelessResetKey[:])
		if err != nil {
			return nil, err
		}
	}
	listener, err := transport.Listen(tlsConfig, quicConfig)
	return listener, WrapError(err)
}

func ListenEarly(conn net.PacketConn, config aTLS.ServerConfig, quicConfig *quic.Config) (EarlyListener, error) {
	return ListenEarlyWithOptions(conn, config, quicConfig, ListenOptions{})
}

func ListenEarlyWithOptions(conn net.PacketConn, config aTLS.ServerConfig, quicConfig *quic.Config, options ListenOptions) (EarlyListener, error) {
	quicConfig = quicConfigWithHandshakeTimeout(quicConfig, config.HandshakeTimeout())
	if quicTLSConfig, isQUICConfig := config.(ServerConfig); isQUICConfig {
		listener, err := quicTLSConfig.ListenEarly(conn, quicConfig)
		return listener, WrapError(err)
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	transport := quic.Transport{Conn: conn, DisableVersionNegotiationPackets: options.DisableVersionNegotiationPackets}
	transport.SetSingleUse(true)
	if options.StatelessReset {
		transport.StatelessResetKey = new(quic.StatelessResetKey)
		_, err = rand.Read(transport.StatelessResetKey[:])
		if err != nil {
			return nil, err
		}
	}
	listener, err := transport.ListenEarly(tlsConfig, quicConfig)
	return listener, WrapError(err)
}

func ConfigureHTTP3(config aTLS.ServerConfig) error {
	if len(config.NextProtos()) == 0 {
		config.SetNextProtos([]string{http3.NextProtoH3})
	}
	if quicTLSConfig, isQUICConfig := config.(ServerConfig); isQUICConfig {
		quicTLSConfig.ConfigureHTTP3()
		return nil
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return err
	}
	http3.ConfigureTLSConfig(tlsConfig)
	return nil
}

type keepSessionKey struct{}

func ContextWithKeepSession(ctx context.Context) context.Context {
	return context.WithValue(ctx, (*keepSessionKey)(nil), true)
}

func KeepSessionFromContext(ctx context.Context) bool {
	keep, _ := ctx.Value((*keepSessionKey)(nil)).(bool)
	return keep
}

// CreationAdmission bounds one SHARED creation of a QUIC client connection.
//
// # Why a hook and why this shape
//
// The three clients (hysteria, hysteria2, TUIC) publish one connection and let concurrent demands
// share the creation that is already in flight. A caller that bounds this process's creation storm
// (resourceguard, a mobile network extension's budget) must be consulted exactly ONCE per creation,
// not once per waiting request, or a burst of N flows is charged N times for one socket. The
// creation is also the only place where the cost is: an established connection is reused without
// any new socket, handshake or authentication.
//
// The hook OWNS the call: it must invoke create exactly once and return its error. A hook that
// refuses must return its own error without calling create, and the shared offer fails as a whole -
// waiters see the refusal instead of a silently opened connection. A nil hook admits everything and
// is the previous behaviour.
//
// For TUIC this covers the authentication write too: `offerNew` performs it before returning, so
// the authentication stage cannot fail after the creation was already accounted as successful.
type CreationAdmission func(ctx context.Context, create func(context.Context) error) error
