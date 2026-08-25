package streaming

import "time"

const (
	InitialRTO = 9 * time.Second
	MinRTO     = 100 * time.Millisecond
	MaxRTO     = 60 * time.Second
)

// RTOEstimator implements the Jacobson/Karels RTT estimator. Call Observe only
// for packets that were acknowledged without retransmission (Karn's rule).
type RTOEstimator struct {
	srtt   time.Duration
	rttvar time.Duration
	rto    time.Duration
	valid  bool
}

func NewRTOEstimator(initial time.Duration) RTOEstimator {
	if initial <= 0 {
		initial = InitialRTO
	}
	return RTOEstimator{rto: clampRTO(initial)}
}

func (r *RTOEstimator) Observe(sample time.Duration) {
	if sample <= 0 {
		sample = time.Nanosecond
	}
	if !r.valid {
		r.srtt = sample
		r.rttvar = sample / 2
		r.valid = true
	} else {
		delta := r.srtt - sample
		if delta < 0 {
			delta = -delta
		}
		r.rttvar = (3*r.rttvar + delta) / 4
		r.srtt = (7*r.srtt + sample) / 8
	}
	r.rto = clampRTO(r.srtt + 4*r.rttvar)
}

func (r *RTOEstimator) Backoff() { r.rto = clampRTO(r.RTO() * 2) }
func (r RTOEstimator) RTO() time.Duration {
	if r.rto <= 0 {
		return InitialRTO
	}
	return r.rto
}
func (r RTOEstimator) SRTT() time.Duration   { return r.srtt }
func (r RTOEstimator) RTTVAR() time.Duration { return r.rttvar }

func clampRTO(value time.Duration) time.Duration {
	if value < MinRTO {
		return MinRTO
	}
	if value > MaxRTO {
		return MaxRTO
	}
	return value
}

// CongestionWindow uses slow start followed by additive increase, and resets
// to a small window after loss. It is intentionally packet-count based because
// Streaming packets are bounded to MaxPacketSize.
type CongestionWindow struct {
	cwnd, ssthresh, credit uint16
}

func NewCongestionWindow(initial uint16) CongestionWindow {
	if initial < MinWindow {
		initial = MinWindow
	}
	return CongestionWindow{cwnd: initial, ssthresh: MaxWindow}
}

func (c *CongestionWindow) Window() uint16 { return c.cwnd }

func (c *CongestionWindow) Acknowledge(count uint16) {
	for ; count != 0 && c.cwnd < MaxWindow; count-- {
		if c.cwnd < c.ssthresh {
			c.cwnd++
			continue
		}
		c.credit++
		if c.credit >= c.cwnd {
			c.credit = 0
			c.cwnd++
		}
	}
}

func (c *CongestionWindow) Loss() {
	threshold := max(c.cwnd/2, MinWindow)
	c.ssthresh = threshold
	c.cwnd = MinWindow
	c.credit = 0
}

func (c CongestionWindow) SlowStartThreshold() uint16 { return c.ssthresh }
