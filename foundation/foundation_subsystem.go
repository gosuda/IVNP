// Package foundation defines shared I2P identities, wire codecs, and verification.
// Wire views borrow their input. Parsing a RouterInfo or LeaseSet does not
// authenticate it; verify its signature before admitting it into trusted state.
package foundation
