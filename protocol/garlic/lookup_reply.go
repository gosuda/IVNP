package garlic

import "cmp"

import (
	"encoding/binary"
	"errors"

	"gosuda.org/ivnp/protocol/garlic/ecies"
	"gosuda.org/ivnp/protocol/i2np"
)

var ErrLookupReply = errors.New("garlic: invalid encrypted DatabaseLookup reply metadata")

// DatabaseLookupReplyWrapper implements the one-time encrypted reply contract
// advertised in DatabaseLookup. ECIES requests use the supplied 32-byte
// ChaCha20-Poly1305 key and one 8-byte ratchet tag. Legacy requests use the
// supplied AES key and first 32-byte session tag. Neither mode can fall back to
// plaintext. MessageID supplies an outer Garlic ID from the router-wide replay
// namespace; production wiring must set it.
type DatabaseLookupReplyWrapper struct {
	MessageID func() uint32
}

// ValidateDatabaseLookupReply rejects incomplete or inconsistent one-time key
// metadata before LookupResponder admits work to its bounded queue.
func (DatabaseLookupReplyWrapper) ValidateDatabaseLookupReply(lookup i2np.DatabaseLookupMessage) error {
	if !lookup.ReplyEncrypted() || len(lookup.ReplyKey) != 32 {
		return ErrLookupReply
	}
	if lookup.ReplyUsesECIES() {
		if lookup.ReplyTagLen != 8 || lookup.ReplyTagCount() != 1 || len(lookup.ReplyTags) != 8 {
			return ErrLookupReply
		}
		return nil
	}
	if lookup.ReplyTagLen != 32 || len(lookup.ReplyTags)%32 != 0 || lookup.ReplyTagCount() == 0 || lookup.ReplyTagCount() > i2np.MaxDatabaseReplyTags {
		return ErrLookupReply
	}
	return nil
}

// WrapDatabaseLookupReply returns an owned I2NP Garlic message containing one
// LOCAL DatabaseStore or DatabaseSearchReply clove under the requester's
// supplied one-time reply key and tag.
func (wrapper DatabaseLookupReplyWrapper) WrapDatabaseLookupReply(lookup i2np.DatabaseLookupMessage, reply i2np.Message) (i2np.Message, error) {
	if err := wrapper.ValidateDatabaseLookupReply(lookup); err != nil {
		return i2np.Message{}, err
	}
	if reply.Header.Type != i2np.DatabaseStore && reply.Header.Type != i2np.DatabaseSearchReply {
		return i2np.Message{}, ErrLookupReply
	}
	if err := i2np.ValidatePayload(reply.Header.Type, reply.Payload); err != nil {
		return i2np.Message{}, ErrLookupReply
	}

	var encrypted []byte
	if lookup.ReplyUsesECIES() {
		var key [32]byte
		var tag [8]byte
		copy(key[:], lookup.ReplyKey)
		copy(tag[:], lookup.ReplyTags)
		defer clear(key[:])
		capacity := 8 + 3 + 10 + len(reply.Payload) + 16
		encrypted = make([]byte, capacity)
		sealed, err := ecies.SealOneTimeReplyExistingSession(encrypted, key, tag, reply, nil)
		if err != nil {
			clear(encrypted)
			return i2np.Message{}, err
		}
		encrypted = sealed
	} else {
		clove := Clove{
			Delivery:   Delivery{Type: DeliveryLocal},
			Message:    reply,
			ID:         reply.Header.ID,
			Expiration: reply.Header.Expiration,
		}
		plainLen, err := CloveSetEncodedLen([]Clove{clove})
		if err != nil {
			return i2np.Message{}, err
		}
		plain := make([]byte, plainLen)
		if _, err = MarshalCloveSetTo(plain, []Clove{clove}, reply.Header.ID, reply.Header.Expiration); err != nil {
			clear(plain)
			return i2np.Message{}, err
		}
		// Existing-session AES has 39 fixed bytes and rounds the body up to
		// a 16-byte block after the clear 32-byte tag.
		bodyLen := (39 + len(plain) + 15) &^ 15
		encrypted = make([]byte, 32+bodyLen)
		sealed, err := EncryptExisting(encrypted, lookup.ReplyTags[:32], lookup.ReplyKey, plain, nil)
		clear(plain)
		if err != nil {
			clear(encrypted)
			return i2np.Message{}, err
		}
		encrypted = sealed
	}

	payload := make([]byte, 4+len(encrypted))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(encrypted)))
	copy(payload[4:], encrypted)
	clear(encrypted)
	return i2np.Message{
		Header:  i2np.Header{Type: i2np.Garlic, ID: wrapper.outerMessageID(reply.Header.ID), Expiration: reply.Header.Expiration},
		Payload: payload,
	}, nil
}

func (wrapper DatabaseLookupReplyWrapper) outerMessageID(inner uint32) uint32 {
	if wrapper.MessageID != nil {
		for range 4 {
			if candidate := wrapper.MessageID(); candidate != 0 && candidate != inner {
				return candidate
			}
		}
	}
	candidate := inner ^ 0xa5a5a5a5
	if candidate == 0 || candidate == inner {
		candidate = inner + 1

		candidate = cmp.Or(candidate, 1)

	}
	return candidate
}
