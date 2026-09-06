package ssu2

import (
	"encoding/binary"
	"errors"
)

var ErrExtensionBlock = errors.New("ssu2: invalid extension block")

// RelayTagRequest asks the peer to allocate an introducer relay tag. The SSU2
// wire request has an empty body; the grant carries the tag and its absolute
// seconds-since-epoch expiration.
type RelayTagRequest struct{}

type RelayTag struct {
	Tag        uint32
	Expiration uint32
}

func MarshalRelayTagRequestBlock(dst []byte, _ RelayTagRequest) ([]byte, error) {
	return MarshalBlock(dst, BlockRelayTagRequest, nil)
}

func ParseRelayTagRequestBlock(data []byte) (RelayTagRequest, error) {
	if len(data) != 0 {
		return RelayTagRequest{}, ErrExtensionBlock
	}
	return RelayTagRequest{}, nil
}

func MarshalRelayTagBlock(dst []byte, relay RelayTag) ([]byte, error) {
	if relay.Tag == 0 || relay.Expiration == 0 {
		return nil, ErrExtensionBlock
	}
	var data [8]byte
	binary.BigEndian.PutUint32(data[:4], relay.Tag)
	binary.BigEndian.PutUint32(data[4:], relay.Expiration)
	return MarshalBlock(dst, BlockRelayTag, data[:])
}

func ParseRelayTagBlock(data []byte) (RelayTag, error) {
	if len(data) != 8 {
		return RelayTag{}, ErrExtensionBlock
	}
	relay := RelayTag{Tag: binary.BigEndian.Uint32(data[:4]), Expiration: binary.BigEndian.Uint32(data[4:])}
	if relay.Tag == 0 || relay.Expiration == 0 {
		return RelayTag{}, ErrExtensionBlock
	}
	return relay, nil
}

// NewToken is a peer-issued address-validation token. Expiration is an
// absolute UTC timestamp in seconds; tokens are opaque to the recipient.
type NewToken struct {
	Token      uint64
	Expiration uint32
}

func MarshalNewTokenBlock(dst []byte, token NewToken) ([]byte, error) {
	if token.Token == 0 || token.Expiration == 0 {
		return nil, ErrExtensionBlock
	}
	var data [12]byte
	binary.BigEndian.PutUint64(data[:8], token.Token)
	binary.BigEndian.PutUint32(data[8:], token.Expiration)
	return MarshalBlock(dst, BlockNewToken, data[:])
}

func ParseNewTokenBlock(data []byte) (NewToken, error) {
	if len(data) != 12 {
		return NewToken{}, ErrExtensionBlock
	}
	token := NewToken{Token: binary.BigEndian.Uint64(data[:8]), Expiration: binary.BigEndian.Uint32(data[8:])}
	if token.Token == 0 || token.Expiration == 0 {
		return NewToken{}, ErrExtensionBlock
	}
	return token, nil
}

// PathChallenge and PathResponse carry an opaque eight-byte probe. Responses
// must echo a live challenge exactly and are never interpreted as numbers.
type PathChallenge struct{ Data [8]byte }
type PathResponse struct{ Data [8]byte }

func MarshalPathChallengeBlock(dst []byte, challenge PathChallenge) ([]byte, error) {
	return MarshalBlock(dst, BlockPathChallenge, challenge.Data[:])
}

func ParsePathChallengeBlock(data []byte) (PathChallenge, error) {
	if len(data) != 8 {
		return PathChallenge{}, ErrExtensionBlock
	}
	var challenge PathChallenge
	copy(challenge.Data[:], data)
	return challenge, nil
}

func MarshalPathResponseBlock(dst []byte, response PathResponse) ([]byte, error) {
	return MarshalBlock(dst, BlockPathResponse, response.Data[:])
}

func ParsePathResponseBlock(data []byte) (PathResponse, error) {
	if len(data) != 8 {
		return PathResponse{}, ErrExtensionBlock
	}
	var response PathResponse
	copy(response.Data[:], data)
	return response, nil
}
