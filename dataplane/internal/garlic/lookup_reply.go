package garlic

import (
	"cmp"
	"encoding/binary"
	"errors"

	dataplanegarlicecies "gosuda.org/ivnp/dataplane/internal/garlic/ecies"
	"gosuda.org/ivnp/foundation"
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
func (DatabaseLookupReplyWrapper) ValidateDatabaseLookupReply(lookup foundation.I2NPDatabaseLookupMessage) error {
	if !lookup.ReplyEncrypted() || len(lookup.ReplyKey) != 32 {
		return ErrLookupReply
	}
	if lookup.ReplyUsesECIES() {
		if lookup.ReplyTagLen != 8 || lookup.ReplyTagCount() != 1 || len(lookup.ReplyTags) != 8 {
			return ErrLookupReply
		}
		return nil
	}
	if lookup.ReplyTagLen != 32 || len(lookup.ReplyTags)%32 != 0 || lookup.ReplyTagCount() == 0 || lookup.ReplyTagCount() > foundation.I2NPMaxDatabaseReplyTags {
		return ErrLookupReply
	}
	return nil
}

// WrapDatabaseLookupReply returns an owned I2NP Garlic message containing one
// LOCAL DatabaseStore or DatabaseSearchReply clove under the requester's
// supplied one-time reply key and tag.
func (wrapper DatabaseLookupReplyWrapper) WrapDatabaseLookupReply(lookup foundation.I2NPDatabaseLookupMessage, reply foundation.I2NPMessage) (foundation.I2NPMessage, error) {
	if err := wrapper.ValidateDatabaseLookupReply(lookup); err != nil {
		return foundation.I2NPMessage{}, err
	}
	if reply.Header.Type != foundation.I2NPDatabaseStore && reply.Header.Type != foundation.I2NPDatabaseSearchReply {
		return foundation.I2NPMessage{}, ErrLookupReply
	}
	if err := foundation.I2NPValidatePayload(reply.Header.Type, reply.Payload); err != nil {
		return foundation.I2NPMessage{}, ErrLookupReply
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
		sealed, err := dataplanegarlicecies.SealOneTimeReplyExistingSession(encrypted, key, tag, reply, nil)
		if err != nil {
			clear(encrypted)
			return foundation.I2NPMessage{}, err
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
			return foundation.I2NPMessage{}, err
		}
		plain := make([]byte, plainLen)
		if _, err = MarshalCloveSetTo(plain, []Clove{clove}, reply.Header.ID, reply.Header.Expiration); err != nil {
			clear(plain)
			return foundation.I2NPMessage{}, err
		}
		// Existing-session AES has 39 fixed bytes and rounds the body up to
		// a 16-byte block after the clear 32-byte tag.
		bodyLen := (39 + len(plain) + 15) &^ 15
		encrypted = make([]byte, 32+bodyLen)
		sealed, err := EncryptExisting(encrypted, lookup.ReplyTags[:32], lookup.ReplyKey, plain, nil)
		clear(plain)
		if err != nil {
			clear(encrypted)
			return foundation.I2NPMessage{}, err
		}
		encrypted = sealed
	}

	payload := make([]byte, 4+len(encrypted))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(encrypted)))
	copy(payload[4:], encrypted)
	clear(encrypted)
	return foundation.I2NPMessage{
		Header:  foundation.I2NPHeader{Type: foundation.I2NPGarlic, ID: wrapper.outerMessageID(reply.Header.ID), Expiration: reply.Header.Expiration},
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
