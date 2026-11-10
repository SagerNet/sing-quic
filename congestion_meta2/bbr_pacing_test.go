package congestion

import (
	"testing"
	"time"

	"github.com/sagernet/quic-go/monotime"
)

// BBR used to call pacer.SentPacket before checking isRetransmittable; an
// ACK-only packet therefore consumed pacing budget.
func TestBBRACKOnlyDoesNotConsumePacer(t *testing.T) {
	sender := NewBbrSenderWithProfile(1200, ProfileStandard)
	sender.SetRTTStatsProvider(testRTTStats{})
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

type testRTTStats struct{}

func (testRTTStats) MinRTT() time.Duration                  { return 50 * time.Millisecond }
func (testRTTStats) LatestRTT() time.Duration               { return 50 * time.Millisecond }
func (testRTTStats) SmoothedRTT() time.Duration             { return 50 * time.Millisecond }
func (testRTTStats) MeanDeviation() time.Duration           { return 5 * time.Millisecond }
func (testRTTStats) MaxAckDelay() time.Duration             { return 25 * time.Millisecond }
func (testRTTStats) PTO(bool) time.Duration                 { return 100 * time.Millisecond }
func (testRTTStats) UpdateRTT(time.Duration, time.Duration) {}
func (testRTTStats) SetMaxAckDelay(time.Duration)           {}
func (testRTTStats) SetInitialRTT(time.Duration)            {}
