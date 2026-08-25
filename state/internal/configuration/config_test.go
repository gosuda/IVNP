package configuration

import (
	"testing"
)

func TestParseI2PDStyleINI(t *testing.T) {
	entries, err := Parse("ipv4 = true\n[ntcp2]\nenabled = true\nport = 4567 # inherited override\n[ssu2]\nenabled = false\n[http]\nhost = \"127.0.0.1\"\n")
	if err != nil || len(entries) != 5 {
		t.Fatalf("Parse=%#v err=%v", entries, err)
	}
	if value, ok := Lookup(entries, "ntcp2", "enabled"); !ok || value != "true" {
		t.Fatalf("ntcp2=%q %t", value, ok)
	}
	if value, ok := Lookup(entries, "", "ipv4"); !ok || value != "true" {
		t.Fatalf("global=%q %t", value, ok)
	}
	if value, ok := Lookup(entries, "http", "host"); !ok || value != "127.0.0.1" {
		t.Fatalf("quoted=%q %t", value, ok)
	}
	if _, err := Parse("[ntcp2]\nenabled=true\n[ntcp2]\nenabled=false\n"); err != ErrMalformed {
		t.Fatalf("duplicate=%v", err)
	}
}
