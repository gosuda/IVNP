package netdb

import (
	"testing"

	foundation "gosuda.org/ivnp/foundation/internal/identity"
)

func TestFloodfillCapabilityUsesCapsOption(t *testing.T) {
	encoded := make([]byte, 16)
	n, err := foundation.MarshalMappingTo(encoded, []foundation.MappingEntry{{Key: []byte("caps"), Value: []byte("XfR")}})
	if err != nil {
		t.Fatal(err)
	}
	mapping, _, err := foundation.ParseMapping(encoded[:n])
	if err != nil {
		t.Fatal(err)
	}
	if !IsFloodfill(RouterInfo{Options: mapping}) {
		t.Fatal("caps=f RouterInfo was not floodfill")
	}
	encoded = make([]byte, 16)
	n, err = foundation.MarshalMappingTo(encoded, []foundation.MappingEntry{{Key: []byte("caps"), Value: []byte("R")}})
	if err != nil {
		t.Fatal(err)
	}
	mapping, _, err = foundation.ParseMapping(encoded[:n])
	if err != nil {
		t.Fatal(err)
	}
	if IsFloodfill(RouterInfo{Options: mapping}) {
		t.Fatal("non-floodfill RouterInfo was accepted")
	}
}
