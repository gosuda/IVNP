package ingress

import (
	"errors"
	"testing"
)

type testReporter struct{ reports []Panic }

func (r *testReporter) ReportRecoveredPanic(p Panic) { r.reports = append(r.reports, p) }

type panickingReporter struct{}

func (panickingReporter) ReportRecoveredPanic(Panic) { panic("reporter failure") }

func TestRecoverContainsPanicAndReportsBoundary(t *testing.T) {
	reporter := new(testReporter)
	var err error
	func() {
		defer Recover(&err, reporter, BoundarySSU2Packet, nil)
		panic(errors.New("fault injection"))
	}()
	if !errors.Is(err, ErrRecoveredPanic) {
		t.Fatalf("recovered error = %v", err)
	}
	if len(reporter.reports) != 1 || reporter.reports[0].Boundary != BoundarySSU2Packet || reporter.reports[0].ValueType == "" {
		t.Fatalf("reports = %#v", reporter.reports)
	}
}

func TestRecoverContainsReporterPanic(t *testing.T) {
	var err error
	func() {
		defer Recover(&err, panickingReporter{}, BoundaryNTCP2Handshake, nil)
		panic("fault injection")
	}()
	if !errors.Is(err, ErrRecoveredPanic) {
		t.Fatalf("recovered error = %v", err)
	}
}
