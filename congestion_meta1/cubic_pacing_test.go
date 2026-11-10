package congestion

import (
	"testing"
	"time"

	"github.com/sagernet/quic-go/monotime"
)

// ACK-only packets must not be charged against the pacer; retransmittable
// packets must still consume budget. The pre-merge code paced both.
func TestCubicACKOnlyDoesNotConsumePacer(t *testing.T) {
	sender := NewCubicSender(DefaultClock{TimeFunc: time.Now}, 1200, false)
	now := monotime.Now()
	initialBudget := sender.pacer.budgetAtLastSent

	sender.OnPacketSent(now, 0, 1, 1200, false)
	if !sender.pacer.lastSentTime.IsZero() {
		t.Fatal("ACK-only packet updated the pacer's last-sent time")
	}
	if sender.pacer.budgetAtLastSent != initialBudget {
		t.Fatalf("ACK-only packet consumed pacing budget: %d -> %d", initialBudget, sender.pacer.budgetAtLastSent)
	}
	if sender.largestSentPacketNumber == 1 {
		t.Fatal("ACK-only packet advanced largestSentPacketNumber")
	}

	sender.OnPacketSent(now, 0, 2, 1200, true)
	if sender.pacer.lastSentTime.IsZero() {
		t.Fatal("retransmittable packet did not update the pacer's last-sent time")
	}
	if sender.pacer.budgetAtLastSent >= initialBudget {
		t.Fatalf("retransmittable packet did not consume pacing budget: %d -> %d", initialBudget, sender.pacer.budgetAtLastSent)
	}
	if sender.largestSentPacketNumber != 2 {
		t.Fatalf("largestSentPacketNumber = %d, want 2", sender.largestSentPacketNumber)
	}
}
