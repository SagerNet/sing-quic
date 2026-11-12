package hysteria

// One shared creation, one admission.
//
// The client publishes one QUIC connection and lets concurrent demands join the creation already in
// flight. The process admission budget must be charged for that ONE creation, not for every waiter,
// and a refusal must fail the shared offer instead of silently opening a connection. These tests
// drive the offer machinery with a dialer that blocks before any QUIC work, so the number of real
// creations is directly observable.

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	qtls "github.com/sagernet/sing-quic"
	M "github.com/sagernet/sing/common/metadata"
)

type admissionDialer struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	err     error
}

func newAdmissionDialer() *admissionDialer {
	return &admissionDialer{entered: make(chan struct{}), release: make(chan struct{})}
}

func (d *admissionDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.calls.Add(1)
	d.once.Do(func() { close(d.entered) })
	select {
	case <-d.release:
		return nil, d.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *admissionDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func newAdmissionClient(dialer *admissionDialer, hook qtls.CreationAdmission) *Client {
	return &Client{
		ctx:           context.Background(),
		dialer:        dialer,
		admitCreation: hook,
	}
}

// TestOneSharedCreationChargesOneAdmission is the core rule: N concurrent demands produce ONE
// creation, and that creation asks for ONE permit.
func TestOneSharedCreationChargesOneAdmission(t *testing.T) {
	dialer := newAdmissionDialer()
	dialer.err = net.ErrClosed
	var admitted, released atomic.Int32
	client := newAdmissionClient(dialer, func(ctx context.Context, create func(context.Context) error) error {
		admitted.Add(1)
		err := create(ctx)
		released.Add(1)
		return err
	})

	const waiters = 8
	start := make(chan struct{})
	results := make(chan error, waiters)
	for index := 0; index < waiters; index++ {
		go func() {
			<-start
			_, err := client.offer(context.Background())
			results <- err
		}()
	}
	close(start)
	<-dialer.entered
	// Let the remaining waiters join the pending offer; none of them may start a creation.
	time.Sleep(30 * time.Millisecond)
	if got := admitted.Load(); got != 1 {
		t.Fatalf("admission was asked %d times for one shared creation, want 1", got)
	}
	if got := dialer.calls.Load(); got != 1 {
		t.Fatalf("%d creation dials happened, want 1", got)
	}
	close(dialer.release)
	for index := 0; index < waiters; index++ {
		if err := <-results; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("waiter got %v, want the creation error", err)
		}
	}
	if got := released.Load(); got != 1 {
		t.Fatalf("the creation released its admission %d times, want 1", got)
	}
}

// TestAdmissionRefusalDoesNotDial pins that the hook OWNS the creation: a refusal must fail the
// shared offer without any socket being opened.
func TestAdmissionRefusalDoesNotDial(t *testing.T) {
	dialer := newAdmissionDialer()
	refusal := errors.New("admission refused")
	client := newAdmissionClient(dialer, func(context.Context, func(context.Context) error) error {
		return refusal
	})
	if _, err := client.offer(context.Background()); !errors.Is(err, refusal) {
		t.Fatalf("offer returned %v, want the admission refusal", err)
	}
	if got := dialer.calls.Load(); got != 0 {
		t.Fatalf("a refused creation dialled %d times, want 0", got)
	}
}

// TestCancelledWaiterDoesNotReleaseTheCreation pins the shared-ownership rule: a waiter that gives
// up stops waiting, but the creation - and its permit - belongs to the client and continues for the
// waiters that are still there.
func TestCancelledWaiterDoesNotReleaseTheCreation(t *testing.T) {
	dialer := newAdmissionDialer()
	dialer.err = net.ErrClosed
	var released atomic.Int32
	client := newAdmissionClient(dialer, func(ctx context.Context, create func(context.Context) error) error {
		err := create(ctx)
		released.Add(1)
		return err
	})

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := client.offer(waiterCtx)
		waiterDone <- err
	}()
	<-dialer.entered
	cancelWaiter()
	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled waiter returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the cancelled waiter did not return")
	}
	if got := released.Load(); got != 0 {
		t.Fatalf("the creation was released while it was still running")
	}

	// The creation is owned by the client, not by the waiter: finishing it releases the permit
	// exactly once, and the cancelled waiter never caused a second creation.
	close(dialer.release)
	deadline := time.Now().Add(2 * time.Second)
	for released.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("the creation released its admission %d times, want 1", released.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if got := dialer.calls.Load(); got != 1 {
		t.Fatalf("%d creation dials happened, want 1", got)
	}
}

// TestNoHookKeepsThePreviousBehaviour is the embedder contract.
func TestNoHookKeepsThePreviousBehaviour(t *testing.T) {
	dialer := newAdmissionDialer()
	dialer.err = net.ErrClosed
	client := newAdmissionClient(dialer, nil)
	close(dialer.release)
	if _, err := client.offer(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("offer returned %v, want the creation error", err)
	}
	if got := dialer.calls.Load(); got != 1 {
		t.Fatalf("%d creation dials happened, want 1", got)
	}
}
