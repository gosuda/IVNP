package router

import (
	"context"

	"gosuda.org/ivnp/dataplane"
)

func PublishPeerTestResult(ctx context.Context, local LocalInfo, result dataplane.RouterPeerTestResult) error {
	switch result.Outcome {
	case dataplane.RouterPeerTestOK:
		local.SetReachability(ReachabilityReachable)
	case dataplane.RouterPeerTestFirewalled, dataplane.RouterPeerTestSymmetricNAT:
		local.SetReachability(ReachabilityFirewalled)
	default:
		return nil
	}
	return local.Publish(ctx)
}
