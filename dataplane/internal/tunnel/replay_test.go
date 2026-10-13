package tunnel

import (
	"errors"
	"testing"
)

func replayTestCell(iv, ciphertext byte) []byte {
	data := make([]byte, 1024)
	for i := range 16 {
		data[i] = iv + byte(i)
		data[16+i] = ciphertext + byte(i)
	}
	return data
}

func TestCellReplayFilterRejectsDuplicateAndSwappedBlocks(t *testing.T) {
	var filter cellReplayFilter
	cell := replayTestCell(1, 70)
	if err := filter.admit(cell); err != nil {
		t.Fatal(err)
	}
	if err := filter.admit(cell); !errors.Is(err, ErrTunnelReplay) {
		t.Fatalf("duplicate = %v", err)
	}
	swapped := append([]byte(nil), cell...)
	copy(swapped[:16], cell[16:32])
	copy(swapped[16:32], cell[:16])
	if err := filter.admit(swapped); !errors.Is(err, ErrTunnelReplay) {
		t.Fatalf("IV/first-block swap = %v", err)
	}
}

func TestCellReplayFilterSeparatesCircuitGenerations(t *testing.T) {
	cell := replayTestCell(2, 80)
	var first, second cellReplayFilter
	if err := first.admit(cell); err != nil {
		t.Fatal(err)
	}
	if err := second.admit(cell); err != nil {
		t.Fatalf("independent circuit rejected cell = %v", err)
	}
}

func TestCellReplayFilterRetainsHistoryAndFailsClosedAtCapacity(t *testing.T) {
	var filter cellReplayFilter
	first := replayTestCell(3, 90)
	if err := filter.admit(first); err != nil {
		t.Fatal(err)
	}
	filter.layers[0].inserted = len(filter.layers[0].words)*64/cellReplayBitsPerEntry - 1
	if err := filter.admit(replayTestCell(4, 91)); err != nil {
		t.Fatalf("at first layer limit = %v", err)
	}
	if err := filter.admit(replayTestCell(5, 92)); err != nil {
		t.Fatalf("growing replay filter = %v", err)
	}
	if filter.current != 1 {
		t.Fatalf("active layer = %d, want 1", filter.current)
	}
	filter.current = cellReplayLayers - 1
	filter.layers[filter.current].words = make([]uint64, cellReplayLayerBits(filter.current)/64)
	filter.layers[filter.current].inserted = len(filter.layers[filter.current].words)*64 / cellReplayBitsPerEntry
	if err := filter.admit(replayTestCell(6, 93)); !errors.Is(err, ErrTunnelReplayCapacity) {
		t.Fatalf("at hard limit = %v", err)
	}
	if err := filter.admit(first); !errors.Is(err, ErrTunnelReplay) {
		t.Fatalf("old replay after filter fills = %v", err)
	}
}
