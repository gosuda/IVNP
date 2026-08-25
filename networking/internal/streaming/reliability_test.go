package streaming

import (
	"testing"
	"time"
)

func TestRTOEstimatorJacobsonKarelsAndBounds(t *testing.T) {
	estimator := NewRTOEstimator(time.Second)
	estimator.Observe(200 * time.Millisecond)
	if got, want := estimator.SRTT(), 200*time.Millisecond; got != want {
		t.Fatalf("first SRTT = %v, want %v", got, want)
	}
	if got, want := estimator.RTTVAR(), 100*time.Millisecond; got != want {
		t.Fatalf("first RTTVAR = %v, want %v", got, want)
	}
	if got, want := estimator.RTO(), 600*time.Millisecond; got != want {
		t.Fatalf("first RTO = %v, want %v", got, want)
	}
	estimator.Observe(300 * time.Millisecond)
	if got, want := estimator.SRTT(), 212500*time.Microsecond; got != want {
		t.Fatalf("second SRTT = %v, want %v", got, want)
	}
	if got, want := estimator.RTTVAR(), 100*time.Millisecond; got != want {
		t.Fatalf("second RTTVAR = %v, want %v", got, want)
	}
	if got, want := estimator.RTO(), 612500*time.Microsecond; got != want {
		t.Fatalf("second RTO = %v, want %v", got, want)
	}
	for range 16 {
		estimator.Backoff()
	}
	if got := estimator.RTO(); got != MaxRTO {
		t.Fatalf("backed off RTO = %v, want %v", got, MaxRTO)
	}
}

func TestCongestionWindowSlowStartAvoidanceAndLoss(t *testing.T) {
	window := NewCongestionWindow(MinWindow)
	window.ssthresh = MinWindow + 2
	window.Acknowledge(2)
	if got, want := window.Window(), uint16(MinWindow+2); got != want {
		t.Fatalf("slow-start window = %d, want %d", got, want)
	}
	window.Acknowledge(window.Window())
	if got, want := window.Window(), uint16(MinWindow+3); got != want {
		t.Fatalf("congestion-avoidance window = %d, want %d", got, want)
	}
	window.Loss()
	if got := window.Window(); got != MinWindow {
		t.Fatalf("loss window = %d, want %d", got, MinWindow)
	}
	if got, want := window.SlowStartThreshold(), uint16((MinWindow+3)/2); got != want {
		t.Fatalf("ssthresh = %d, want %d", got, want)
	}
}
