package garlic

// GarlicReplyKey is the one-time existing-session key material derived for an
// outbound short-build endpoint reply. The garlic receiver consumes it before
// authenticating the packet, then routes the decrypted clove through Router.
type GarlicReplyKey struct {
	Key       [32]byte
	Tag       [8]byte
	ExpiresAt uint64
}

// GarlicReplyKeyRegistry retains bounded one-time reply keys for the garlic
// receiver. The receiver consumes the tag before attempting decryption; an
// authenticated clove is then delivered through router dispatch.
type GarlicReplyKeyRegistry interface {
	RegisterGarlicReplyKey(GarlicReplyKey) error
	RemoveGarlicReplyKey([8]byte)
}
