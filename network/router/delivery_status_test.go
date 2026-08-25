package router

import (
	"testing"

	"gosuda.org/ivnp/protocol/i2np"
)

type statusTestHandler struct {
	id    uint32
	calls int
}

func (h *statusTestHandler) HandleDeliveryStatus(status i2np.DeliveryStatusMessage) bool {
	h.calls++
	return status.MessageID == h.id
}

func TestDeliveryStatusMuxClaimsOnceAndCountsUnknown(t *testing.T) {
	publication := &statusTestHandler{id: 7}
	health := &statusTestHandler{id: 1 << 31}
	mux := NewDeliveryStatusMux(publication, health)
	if !mux.HandleDeliveryStatus(i2np.DeliveryStatusMessage{MessageID: 7}) || publication.calls != 1 || health.calls != 0 {
		t.Fatalf("publication dispatch = %d/%d", publication.calls, health.calls)
	}
	if !mux.HandleDeliveryStatus(i2np.DeliveryStatusMessage{MessageID: 1 << 31}) || health.calls != 1 {
		t.Fatalf("health dispatch = %d", health.calls)
	}
	if mux.HandleDeliveryStatus(i2np.DeliveryStatusMessage{MessageID: 9}) || mux.Unmatched() != 1 {
		t.Fatalf("unknown status = %d", mux.Unmatched())
	}
}
