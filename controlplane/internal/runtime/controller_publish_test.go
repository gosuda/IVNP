package noderuntime

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestRequestDestinationPublicationDebounces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &Controller{
			ctx:                    t.Context(),
			destinationPublishWake: make(chan *destinationRuntime, 4),
			publishDebounce:        50 * time.Millisecond,
		}
		runtime := &destinationRuntime{}
		d.requestDestinationPublication(runtime)
		synctest.Wait()
		select {
		case queued := <-d.destinationPublishWake:
			queued.publishQueued.Store(destinationMaintenanceIdle)
			if queued != runtime {
				t.Fatalf("leading publish wake = %v, want destination runtime", queued)
			}
		default:
			t.Fatal("leading publish wake was not enqueued immediately")
		}

		d.requestDestinationPublication(runtime)
		d.requestDestinationPublication(runtime)
		<-time.After(d.publishDebounce - time.Millisecond)
		synctest.Wait()
		select {
		case <-d.destinationPublishWake:
			t.Fatal("trailing publish wake fired before debounce window elapsed")
		default:
		}

		<-time.After(time.Millisecond)
		synctest.Wait()
		select {
		case queued := <-d.destinationPublishWake:
			queued.publishQueued.Store(destinationMaintenanceIdle)
			if queued != runtime {
				t.Fatalf("trailing publish wake = %v, want destination runtime", queued)
			}
		default:
			t.Fatal("trailing publish wake did not fire at debounce expiry")
		}

		<-time.After(4 * d.publishDebounce)
		synctest.Wait()
		select {
		case <-d.destinationPublishWake:
			t.Fatal("publication wake storm: uncoalesced event inside debounce window")
		default:
		}
	})
}
