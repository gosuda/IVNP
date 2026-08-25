package netdb

import (
	"testing"

	"gosuda.org/ivnp"
)

func TestFloodfillCapabilityUsesCapsOption(t *testing.T) {
	encoded := make([]byte, 16)
	n, err := ivnp.MarshalMappingTo(encoded, []ivnp.MappingEntry{{Key: []byte("caps"), Value: []byte("XfR")}})
	if err != nil {
		t.Fatal(err)
	}
	mapping, _, err := ivnp.ParseMapping(encoded[:n])
	if err != nil {
		t.Fatal(err)
	}
	if !IsFloodfill(RouterInfo{Options: mapping}) {
		t.Fatal("caps=f RouterInfo was not floodfill")
	}
	encoded = make([]byte, 16)
	n, err = ivnp.MarshalMappingTo(encoded, []ivnp.MappingEntry{{Key: []byte("caps"), Value: []byte("R")}})
	if err != nil {
		t.Fatal(err)
	}
	mapping, _, err = ivnp.ParseMapping(encoded[:n])
	if err != nil {
		t.Fatal(err)
	}
	if IsFloodfill(RouterInfo{Options: mapping}) {
		t.Fatal("non-floodfill RouterInfo was accepted")
	}
}
