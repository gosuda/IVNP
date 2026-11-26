package router

import (
	"testing"
	"testing/synctest"
	"time"

	dataplanessu2 "gosuda.org/ivnp/dataplane/internal/transport/ssu2"
	"gosuda.org/ivnp/internal/simnet"
)

// sendSSU2TokenRequests sends count TokenRequests from conn and returns how
// many Retry packets came back.
func sendSSU2TokenRequests(t *testing.T, net_ *simnet.Network, conn *simnet.UDPConn, target ssu2HalfOpenTarget, firstID uint64, count int) int {
	t.Helper()
	payload := ssu2HalfOpenPayload(t)
	for index := range count {
		id := firstID + uint64(index)*2
		packet, err := dataplanessu2.BuildTokenRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), target.intro, id, id+1, 0, payload, 2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = conn.WriteTo(packet, target.addr); err != nil {
			t.Fatal(err)
		}
		net_.Advance(time.Millisecond)
	}
	retries := 0
	reply := make([]byte, dataplanessu2.MaxIPv4PacketLen)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, _, err := conn.ReadFrom(reply)
		if err != nil {
			return retries
		}
		if _, _, err = dataplanessu2.ParseRetry(reply[:n], target.intro, 2); err == nil {
			retries++
		}
	}
}

// TestSSU2RetryRateLimitedPerSource sends a burst of TokenRequests from one
// source, as a reflection attack with a spoofed victim address would. Only a
// small number of Retry packets may go back to that source per window, while
// another source and the same source in a later window are still answered.
func TestSSU2RetryRateLimitedPerSource(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		net_ := newSSU2SimNetwork(t)
		bobConn := newSSU2SimConn(t, net_, "bob")
		victimConn := newSSU2SimConn(t, net_, "victim")
		carolConn := newSSU2SimConn(t, net_, "carol")
		bob, bobStatic, bobIntro := newSSU2TestLocal(t, bobConn.LocalAddr().String())
		bobManager, err := NewSSU2Manager(SSU2ManagerConfig{NetworkID: 2, Peers: newTransportTestPeers(), StaticPrivate: bobStatic, IntroKey: bobIntro})
		if err != nil {
			t.Fatal(err)
		}
		startSSU2SimManager(t, t.Context(), bobManager, bobConn, bob, nil)
		t.Cleanup(func() { closeSSU2LiveManager(t, bobManager) })
		target := newSSU2HalfOpenTarget(t, bobConn, bobStatic, bobIntro)

		const burst = 3 * ssu2MaxRetriesPerSource
		if got := sendSSU2TokenRequests(t, net_, victimConn, target, 1000, burst); got != ssu2MaxRetriesPerSource {
			t.Fatalf("Retry packets reflected to one source = %d of %d TokenRequests, want %d", got, burst, ssu2MaxRetriesPerSource)
		}
		initiator, err := dataplanessu2.NewInitiator(target.static, target.intro, 7000, 7001, 2)
		if err != nil {
			t.Fatal(err)
		}
		defer initiator.ReleaseSensitive()
		request, err := initiator.BuildSessionRequest(make([]byte, dataplanessu2.MaxIPv4PacketLen), ssu2HalfOpenPayload(t), 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = victimConn.WriteTo(request, target.addr); err != nil {
			t.Fatal(err)
		}
		if err = victimConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, _, err = victimConn.ReadFrom(make([]byte, dataplanessu2.MaxIPv4PacketLen)); err == nil {
			t.Fatal("a token-less SessionRequest drew a Retry after the source used its budget")
		}
		if got := sendSSU2TokenRequests(t, net_, carolConn, target, 5000, 1); got != 1 {
			t.Fatalf("Retry packets to an unrelated source = %d, want 1", got)
		}
		net_.Advance(2 * time.Second)
		if got := sendSSU2TokenRequests(t, net_, victimConn, target, 9000, 1); got != 1 {
			t.Fatalf("Retry packets to the source in a later window = %d, want 1", got)
		}
	})
}
