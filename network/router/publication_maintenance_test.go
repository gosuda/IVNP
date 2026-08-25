package router

import (
	"context"
	"errors"
	"testing"
)

type maintenanceRouterInfo struct {
	calls int
	err   error
}

func (r *maintenanceRouterInfo) Publish(context.Context) error {
	r.calls++
	return r.err
}

type maintenanceLeaseSet struct {
	calls int
	sent  int
	err   error
}

func (p *maintenanceLeaseSet) Maintain(context.Context) (int, error) {
	p.calls++
	return p.sent, p.err
}

func TestPublicationMaintenanceRefreshesIndependentPublishers(t *testing.T) {
	now := uint64(100)
	routerInfo := new(maintenanceRouterInfo)
	leaseSet := &maintenanceLeaseSet{sent: 2}
	maintenance, err := NewPublicationMaintenance(PublicationMaintenanceConfig{
		RouterInfo: routerInfo, LeaseSet: leaseSet, Now: func() uint64 { return now }, RouterInfoRefresh: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := maintenance.Maintain(context.Background())
	if err != nil || !result.RouterInfoRefreshed || result.LeaseSetPublications != 2 || routerInfo.calls != 1 || leaseSet.calls != 1 {
		t.Fatalf("first maintenance = %#v, %v; calls=%d/%d", result, err, routerInfo.calls, leaseSet.calls)
	}
	now += 5
	result, err = maintenance.Maintain(context.Background())
	if err != nil || result.RouterInfoRefreshed || routerInfo.calls != 1 || leaseSet.calls != 2 {
		t.Fatalf("before refresh = %#v, %v; calls=%d/%d", result, err, routerInfo.calls, leaseSet.calls)
	}
	now += 5
	result, err = maintenance.Maintain(context.Background())
	if err != nil || !result.RouterInfoRefreshed || routerInfo.calls != 2 || leaseSet.calls != 3 {
		t.Fatalf("due refresh = %#v, %v; calls=%d/%d", result, err, routerInfo.calls, leaseSet.calls)
	}
	routerInfo.err = errors.New("router publication failed")
	now += 10
	_, err = maintenance.Maintain(context.Background())
	if !errors.Is(err, routerInfo.err) || routerInfo.calls != 3 || leaseSet.calls != 4 {
		t.Fatalf("independent error maintenance = %v; calls=%d/%d", err, routerInfo.calls, leaseSet.calls)
	}
}
