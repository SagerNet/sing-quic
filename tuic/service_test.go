package tuic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/gofrs/uuid/v5"
)

// A session authenticates once and then relays every later stream without
// consulting the user table again, so removing a user from it has to close
// that user's sessions as well.
func TestUpdateUsersClosesRemovedUserSessions(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	userUUID := uuid.Must(uuid.NewV4())
	handler := &testHandler{connections: make(chan net.Conn, 1)}
	certificate := generateCertificate(t)

	service, err := NewService[string](ServiceOptions{
		Context: ctx,
		Logger:  logger.NOP(),
		TLSConfig: &testTLSConfig{config: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{"tuic-test"},
		}},
		Handler: handler,
	})
	if err != nil {
		t.Fatal(err)
	}
	service.UpdateUsers([]string{"alice"}, [][16]byte{userUUID}, []string{"password"})

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	err = service.Start(packetConn)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	client, err := NewClient(ClientOptions{
		Context:       ctx,
		Dialer:        N.SystemDialer,
		ServerAddress: M.SocksaddrFromNet(packetConn.LocalAddr()),
		TLSConfig: &testTLSConfig{config: &tls.Config{
			ServerName:         "example.org",
			InsecureSkipVerify: true,
			NextProtos:         []string{"tuic-test"},
		}},
		UUID:     userUUID,
		Password: "password",
	})
	if err != nil {
		t.Fatal(err)
	}

	clientConn, err := client.DialConn(ctx, M.ParseSocksaddr("example.org:80"))
	if err != nil {
		t.Fatal(err)
	}
	// The request header rides on the first write, so nothing reaches the
	// handler until the client sends something.
	_, err = clientConn.Write([]byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.connections:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for the relayed connection")
	}

	service.UpdateUsers(nil, nil, nil)

	readDone := make(chan error, 1)
	go func() {
		_, readErr := clientConn.Read(make([]byte, 1))
		readDone <- readErr
	}()
	select {
	case readErr := <-readDone:
		if readErr == nil {
			t.Fatal("expected the relayed connection to fail")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session of a removed user stayed alive")
	}
}

type testHandler struct {
	connections chan net.Conn
}

func (h *testHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.connections <- conn
}

func (h *testHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
}

func generateCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.org"},
		DNSNames:     []string{"example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certificate, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{certificate}, PrivateKey: key}
}

type testTLSConfig struct {
	config *tls.Config
}

func (c *testTLSConfig) ServerName() string {
	return c.config.ServerName
}

func (c *testTLSConfig) SetServerName(serverName string) {
	c.config.ServerName = serverName
}

func (c *testTLSConfig) NextProtos() []string {
	return c.config.NextProtos
}

func (c *testTLSConfig) SetNextProtos(nextProto []string) {
	c.config.NextProtos = nextProto
}

func (c *testTLSConfig) HandshakeTimeout() time.Duration {
	return 0
}

func (c *testTLSConfig) SetHandshakeTimeout(timeout time.Duration) {
}

func (c *testTLSConfig) STDConfig() (*aTLS.STDConfig, error) {
	return c.config, nil
}

func (c *testTLSConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	return tls.Client(conn, c.config), nil
}

func (c *testTLSConfig) Server(conn net.Conn) (aTLS.Conn, error) {
	return tls.Server(conn, c.config), nil
}

func (c *testTLSConfig) Clone() aTLS.Config {
	return &testTLSConfig{config: c.config.Clone()}
}

func (c *testTLSConfig) Start() error {
	return nil
}

func (c *testTLSConfig) Close() error {
	return nil
}
