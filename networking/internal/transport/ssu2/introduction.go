package ssu2

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ErrIntroduction = errors.New("ssu2: invalid introduction block")

var (
	relayRequestPrologue  = "RelayRequestData"
	relayResponsePrologue = "RelayAgreementOK"
)

// RelayRequest is Alice's signed request to an established introducer. The
// Signature aliases a parsed packet and must be copied when retained.
type RelayRequest struct {
	Nonce     uint32
	RelayTag  uint32
	Timestamp uint32
	Endpoint  netip.AddrPort
	Signature []byte
}

// RelayIntro is Bob's forwarding of a RelayRequest to Charlie.
type RelayIntro struct {
	AliceHash [32]byte
	Request   RelayRequest
}

// RelayResponse is Charlie's signed answer, or Bob's signed rejection. Token
// is present only for an accepted response.
type RelayResponse struct {
	Code      uint8
	Nonce     uint32
	Timestamp uint32
	Endpoint  netip.AddrPort
	Signature []byte
	Token     uint64
	HasToken  bool
}

// RelayConnectionIDs derives the mandatory Hole Punch connection IDs from a
// relay nonce.
func RelayConnectionIDs(nonce uint32) (destinationID, sourceID uint64) {
	destinationID = uint64(nonce)<<32 | uint64(nonce)
	return destinationID, ^destinationID
}

// MarshalRelayRequestBlock appends a strict Relay Request block.
func MarshalRelayRequestBlock(dst []byte, request RelayRequest) ([]byte, error) {
	if len(request.Signature) == 0 {
		return nil, ErrIntroduction
	}
	data := make([]byte, 1, 1+14+18+len(request.Signature))
	unsigned, err := appendRelayRequestUnsigned(data, request)
	if err != nil {
		return nil, err
	}
	data = append(unsigned, request.Signature...)
	return MarshalBlock(dst, BlockRelayRequest, data)
}

// ParseRelayRequestBlock parses one Relay Request block body.
func ParseRelayRequestBlock(data []byte) (RelayRequest, error) {
	if len(data) < 1 || data[0] != 0 {
		return RelayRequest{}, ErrIntroduction
	}
	return parseRelayRequest(data[1:])
}

// RelayRequestSignatureInput appends the exact byte sequence Alice signs for
// a Relay Request. bobHash and charlieHash must each be 32 bytes.
func RelayRequestSignatureInput(dst, bobHash, charlieHash []byte, request RelayRequest) ([]byte, error) {
	if len(bobHash) != 32 || len(charlieHash) != 32 {
		return nil, ErrIntroduction
	}
	dst = append(dst, relayRequestPrologue...)
	dst = append(dst, bobHash...)
	dst = append(dst, charlieHash...)
	return appendRelayRequestUnsigned(dst, request)
}

// MarshalRelayIntroBlock appends a strict Relay Intro block containing Bob's
// unmodified forwarding of Alice's signed Relay Request.
func MarshalRelayIntroBlock(dst []byte, intro RelayIntro) ([]byte, error) {
	if len(intro.Request.Signature) == 0 {
		return nil, ErrIntroduction
	}
	data := make([]byte, 33, 33+14+18+len(intro.Request.Signature))
	copy(data[1:], intro.AliceHash[:])
	unsigned, err := appendRelayRequestUnsigned(data, intro.Request)
	if err != nil {
		return nil, err
	}
	data = append(unsigned, intro.Request.Signature...)
	return MarshalBlock(dst, BlockRelayIntro, data)
}

// ParseRelayIntroBlock parses one Relay Intro block body.
func ParseRelayIntroBlock(data []byte) (RelayIntro, error) {
	if len(data) < 33 || data[0] != 0 {
		return RelayIntro{}, ErrIntroduction
	}
	var intro RelayIntro
	copy(intro.AliceHash[:], data[1:33])
	request, err := parseRelayRequest(data[33:])
	if err != nil {
		return RelayIntro{}, err
	}
	intro.Request = request
	return intro, nil
}

// MarshalRelayResponseBlock appends a strict Relay Response block.
func MarshalRelayResponseBlock(dst []byte, response RelayResponse) ([]byte, error) {
	if !validRelayResponse(response) {
		return nil, ErrIntroduction
	}
	data := make([]byte, 2, 2+10+18+len(response.Signature)+8)
	data[1] = response.Code
	unsigned, err := appendRelayResponseUnsigned(data, response)
	if err != nil {
		return nil, err
	}
	data = append(unsigned, response.Signature...)
	if response.HasToken {
		var token [8]byte
		binary.BigEndian.PutUint64(token[:], response.Token)
		data = append(data, token[:]...)
	}
	return MarshalBlock(dst, BlockRelayResponse, data)
}

// ParseRelayResponseBlock parses one Relay Response block body.
func ParseRelayResponseBlock(data []byte) (RelayResponse, error) {
	if len(data) < 13 || data[0] != 0 {
		return RelayResponse{}, ErrIntroduction
	}
	response := RelayResponse{Code: data[1],
		Nonce:     binary.BigEndian.Uint32(data[2:6]),
		Timestamp: binary.BigEndian.Uint32(data[6:10])}
	if data[10] != Version {
		return RelayResponse{}, ErrIntroduction
	}
	endpointSize := int(data[11])
	if response.Code == 0 {
		if endpointSize != 6 && endpointSize != 18 || len(data) < 12+endpointSize+1+8 {
			return RelayResponse{}, ErrIntroduction
		}
		endpoint, err := parseRelayEndpoint(data[12 : 12+endpointSize])
		if err != nil {
			return RelayResponse{}, err
		}
		response.Endpoint = endpoint
		end := len(data) - 8
		response.Signature = data[12+endpointSize : end]
		response.Token = binary.BigEndian.Uint64(data[end:])
		response.HasToken = true
	} else {
		if endpointSize != 0 || len(data) < 13 {
			return RelayResponse{}, ErrIntroduction
		}
		response.Signature = data[12:]
	}
	if !validRelayResponse(response) {
		return RelayResponse{}, ErrIntroduction
	}
	return response, nil
}

// RelayResponseSignatureInput appends the exact byte sequence Charlie or Bob
// signs for a Relay Response. bobHash must be the 32-byte introducer hash.
func RelayResponseSignatureInput(dst, bobHash []byte, response RelayResponse) ([]byte, error) {
	if len(bobHash) != 32 || !validRelayResponseFields(response) {
		return nil, ErrIntroduction
	}
	dst = append(dst, relayResponsePrologue...)
	dst = append(dst, bobHash...)
	return appendRelayResponseUnsigned(dst, response)
}

func parseRelayRequest(data []byte) (RelayRequest, error) {
	if len(data) < 14+6+1 || data[12] != Version {
		return RelayRequest{}, ErrIntroduction
	}
	endpointSize := int(data[13])
	if endpointSize != 6 && endpointSize != 18 || len(data) < 14+endpointSize+1 {
		return RelayRequest{}, ErrIntroduction
	}
	endpoint, err := parseRelayEndpoint(data[14 : 14+endpointSize])
	if err != nil {
		return RelayRequest{}, err
	}
	return RelayRequest{
		Nonce:     binary.BigEndian.Uint32(data[:4]),
		RelayTag:  binary.BigEndian.Uint32(data[4:8]),
		Timestamp: binary.BigEndian.Uint32(data[8:12]),
		Endpoint:  endpoint,
		Signature: data[14+endpointSize:],
	}, nil
}

func appendRelayRequestUnsigned(dst []byte, request RelayRequest) ([]byte, error) {
	endpoint, err := appendRelayEndpoint(nil, request.Endpoint)
	if err != nil {
		return nil, err
	}
	var fixed [14]byte
	binary.BigEndian.PutUint32(fixed[:4], request.Nonce)
	binary.BigEndian.PutUint32(fixed[4:8], request.RelayTag)
	binary.BigEndian.PutUint32(fixed[8:12], request.Timestamp)
	fixed[12] = Version
	fixed[13] = byte(len(endpoint))
	dst = append(dst, fixed[:]...)
	return append(dst, endpoint...), nil
}

func appendRelayResponseUnsigned(dst []byte, response RelayResponse) ([]byte, error) {
	var endpoint []byte
	var err error
	if response.Code == 0 {
		endpoint, err = appendRelayEndpoint(nil, response.Endpoint)
		if err != nil {
			return nil, err
		}
	}
	var fixed [10]byte
	binary.BigEndian.PutUint32(fixed[:4], response.Nonce)
	binary.BigEndian.PutUint32(fixed[4:8], response.Timestamp)
	fixed[8] = Version
	fixed[9] = byte(len(endpoint))
	dst = append(dst, fixed[:]...)
	return append(dst, endpoint...), nil
}

func validRelayResponse(response RelayResponse) bool {
	return len(response.Signature) != 0 && validRelayResponseFields(response)
}

func validRelayResponseFields(response RelayResponse) bool {
	if response.Code == 0 {
		return response.HasToken && validRelayEndpoint(response.Endpoint)
	}
	return !response.HasToken && !response.Endpoint.IsValid()
}

func appendRelayEndpoint(dst []byte, endpoint netip.AddrPort) ([]byte, error) {
	if !validRelayEndpoint(endpoint) {
		return nil, ErrIntroduction
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], endpoint.Port())
	dst = append(dst, port[:]...)
	address := endpoint.Addr()
	if address.Is4() {
		v4 := address.As4()
		return append(dst, v4[:]...), nil
	}
	v6 := address.As16()
	return append(dst, v6[:]...), nil
}

func parseRelayEndpoint(data []byte) (netip.AddrPort, error) {
	if len(data) != 6 && len(data) != 18 {
		return netip.AddrPort{}, ErrIntroduction
	}
	port := binary.BigEndian.Uint16(data[:2])
	address, ok := netip.AddrFromSlice(data[2:])
	if !ok || port == 0 || address.IsUnspecified() || address.Is4In6() {
		return netip.AddrPort{}, ErrIntroduction
	}
	return netip.AddrPortFrom(address, port), nil
}

func validRelayEndpoint(endpoint netip.AddrPort) bool {
	address := endpoint.Addr()
	return endpoint.IsValid() && endpoint.Port() != 0 && !address.IsUnspecified() && !address.Is4In6() && (address.Is4() || address.Is6())
}
