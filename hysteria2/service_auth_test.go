package hysteria2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

func TestConcurrentSessionRegistration(t *testing.T) {
	service := &Service[string]{sessions: make(map[*serverSession[string]]string)}
	service.UpdateUsers([]string{"account", "other"}, []string{"credential", "second"})
	session := &serverSession[string]{Service: service, ctx: context.Background()}
	var firstCount atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			service.UpdateUsers([]string{"other", "account"}, []string{"second", "credential"})
			ok, first := session.authorize("credential", true)
			if !ok {
				t.Error("valid credential was rejected")
			}
			if first {
				firstCount.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if firstCount.Load() != 1 || session.authUser != "account" || len(service.sessions) != 1 {
		t.Fatal("concurrent authentication did not produce one stable binding")
	}
	// A closed parent cannot be enrolled again even when the credential is valid.
	service.usersMu.Lock()
	detached := service.detachSessionsLocked(func(user, _ string) bool { return user == "account" })
	service.usersMu.Unlock()
	if len(detached) != 1 || session.active() {
		t.Fatal("expected one detached session")
	}
	if ok, _ := session.authorize("credential", true); ok {
		t.Fatal("closed parent re-enrolled")
	}
}

// Use real transport connections so the assertion observes the peer closing,
// independently of registry bookkeeping. The fixture only listens on loopback.
func TestUpdateUsersClosesChangedBindings(t *testing.T) {
	certificate := httptest.NewUnstartedServer(http.NotFoundHandler())
	certificate.StartTLS()
	defer certificate.Close()
	tlsConf := certificate.TLS.Clone()
	tlsConf.NextProtos = []string{"h3"}
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConf, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	service := &Service[string]{sessions: make(map[*serverSession[string]]string)}
	service.UpdateUsers([]string{"a", "b", "c"}, []string{"key-a", "key-b", "key-c"})
	open := func(password string) (*serverSession[string], *quic.Conn) {
		t.Helper()
		peer, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{"h3"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { peer.CloseWithError(0, "") })
		conn, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sessionCtx, stop := context.WithCancel(ctx)
		s := &serverSession[string]{Service: service, ctx: sessionCtx, cancel: stop, quicConn: conn}
		t.Cleanup(s.close)
		if ok, first := s.authorize(password, true); !ok || !first {
			t.Fatal("expected a new binding")
		}
		return s, peer
	}
	closed := func(conn *quic.Conn) {
		t.Helper()
		select {
		case <-conn.Context().Done():
		case <-ctx.Done():
			t.Fatal("peer did not observe a QUIC close")
		}
	}
	a, first := open("key-a")
	_, second := open("key-a")
	b, kept := open("key-b")
	_, reassigned := open("key-c")
	service.UpdateUsers([]string{"b", "a", "d"}, []string{"key-b", "new-key-a", "key-c"})
	closed(first)
	closed(second)
	closed(reassigned)
	if !b.active() || kept.Context().Err() != nil {
		t.Fatal("unchanged binding was closed")
	}
	service.UpdateUsers([]string{"a", "b"}, []string{"key-a", "key-b"})
	if ok, _ := a.authorize("key-a", true); ok {
		t.Fatal("credential restoration reactivated an old transport")
	}
	_, fresh := open("key-a")
	service.CloseUserSessions("b")
	closed(kept)
	if fresh.Context().Err() != nil {
		t.Fatal("kick closed an unrelated session")
	}
	service.UpdateUsers(nil, nil)
	closed(fresh)
}
