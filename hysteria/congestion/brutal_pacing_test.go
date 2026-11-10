package congestion

import (
	"testing"

	"github.com/sagernet/quic-go/monotime"
	"github.com/sagernet/sing/common/logger"
)

// Brutal had the same ordering bug: ACK-only sends consumed pacer budget.
func TestBrutalACKOnlyDoesNotConsumePacer(t *testing.T) {
	sender := NewBrutalSender(100*1000*1000, 1200, false, logger.NOP())
	now := monotime.Now()
	initialBudget := sender.pacer.budgetAtLastSent

	sender.OnPacketSent(now, 0, 1, 1200, false)
	if !sender.pacer.lastSentTime.IsZero() {
		t.Fatal("ACK-only packet updated the pacer's last-sent time")
	}
	if sender.pacer.budgetAtLastSent != initialBudget {
		t.Fatalf("ACK-only packet consumed pacing budget: %d -> %d", initialBudget, sender.pacer.budgetAtLastSent)
	}

	sender.OnPacketSent(now, 0, 2, 1200, true)
	if sender.pacer.lastSentTime.IsZero() {
		t.Fatal("retransmittable packet did not update the pacer's last-sent time")
	}
}
