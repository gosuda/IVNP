package overlaybridge

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"gosuda.org/ivnp/overlay"
)

// The admission frame is the post-handshake channel-binding exchange:
// u16 totalLen | magic | scope | u16 credLen | credential | pskMAC. The MAC
// covers everything after totalLen, computed over the bytes as received.
// The reply is u8 status | u16 totalLen | replyMagic | scope | u16 credLen |
// credential; a zero status byte is a bare rejection.

var (
	errScopeMalformed  = errors.New("overlaybridge: malformed scope")
	errScopeZeroField  = errors.New("overlaybridge: scope carries a zero field")
	errFrameLength     = errors.New("overlaybridge: frame length out of bounds")
	errFrameMagic      = errors.New("overlaybridge: bad frame magic")
	errCredLength      = errors.New("overlaybridge: credential length does not fit the frame")
	errReplyBound      = errors.New("overlaybridge: reply exceeds the frame bound")
	errReplyLength     = errors.New("overlaybridge: reply length out of bounds")
	errReplyMagic      = errors.New("overlaybridge: bad reply magic")
	errReplyCredLength = errors.New("overlaybridge: reply credential length does not fit")
)

func encodeScope(scope overlay.ChannelScope, dst *bytes.Buffer) {
	dst.Write(scope.Fabric[:])
	dst.WriteByte(byte(scope.NetworkID))
	dst.Write(scope.Realm[:])
	dst.Write(scope.Endpoint[:])
	var buf [8]byte
	binary.BigEndian.PutUint16(buf[:2], scope.Port)
	dst.Write(buf[:2])
	dst.WriteByte(scope.Selector)
	dst.WriteByte(byte(scope.Protocol))
	dst.WriteByte(byte(scope.Class))
	dst.WriteByte(byte(scope.Exposure))
	binary.BigEndian.PutUint64(buf[:8], scope.PolicyGen)
	dst.Write(buf[:8])
}

func decodeScope(src []byte) (overlay.ChannelScope, error) {
	var scope overlay.ChannelScope
	if len(src) != frameFixedBytes {
		return scope, errScopeMalformed
	}
	copy(scope.Fabric[:], src[:32])
	scope.NetworkID = overlay.WireNetworkID(src[32])
	copy(scope.Realm[:], src[33:65])
	copy(scope.Endpoint[:], src[65:97])
	scope.Port = binary.BigEndian.Uint16(src[97:99])
	scope.Selector = src[99]
	scope.Protocol = overlay.EndpointProtocol(src[100])
	scope.Class = overlay.RouteClass(src[101])
	scope.Exposure = overlay.PrivacyClass(src[102])
	scope.PolicyGen = binary.BigEndian.Uint64(src[103:111])
	if scope.NetworkID == 0 || scope.Protocol == 0 || scope.Class == 0 || scope.Exposure == 0 {
		return scope, errScopeZeroField
	}
	return scope, nil
}

// encodeFrame builds the client's admission frame; key nil means no proof.
func encodeFrame(scope overlay.ChannelScope, credential, key, exporter []byte) ([]byte, error) {
	var body bytes.Buffer
	body.WriteString(frameMagic)
	encodeScope(scope, &body)
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(credential)))
	body.Write(size[:])
	body.Write(credential)
	mac := make([]byte, 32)
	if len(key) > 0 {
		copy(mac, admissionMAC(key, exporter, body.Bytes()))
	}
	body.Write(mac)
	if body.Len() > frameMaxBytes-2 {
		return nil, overlay.CodeInvalidConfig.Wrap("admission material exceeds the frame bound")
	}
	out := make([]byte, 0, body.Len()+2)
	binary.BigEndian.PutUint16(size[:], uint16(body.Len()))
	out = append(out, size[:]...)
	out = append(out, body.Bytes()...)
	return out, nil
}

// readFrame parses one inbound admission frame under the byte bound.
// rawScope is the exact scope slice — the MAC input — not a re-encoding.
func readFrame(r io.Reader) (scope overlay.ChannelScope, credential, mac, rawScope []byte, err error) {
	var head [2]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return
	}
	total := int(binary.BigEndian.Uint16(head[:]))
	if total < len(frameMagic)+frameFixedBytes+2+32 || total > frameMaxBytes-2 {
		err = errFrameLength
		return
	}
	body := make([]byte, total)
	if _, err = io.ReadFull(r, body); err != nil {
		return
	}
	if !bytes.HasPrefix(body, []byte(frameMagic)) {
		err = errFrameMagic
		return
	}
	scope, err = decodeScope(body[len(frameMagic) : len(frameMagic)+frameFixedBytes])
	if err != nil {
		return
	}
	rawScope = body[:len(body)-32]
	rest := body[len(frameMagic)+frameFixedBytes:]
	credLen := int(binary.BigEndian.Uint16(rest[:2]))
	if len(rest) != 2+credLen+32 {
		err = errCredLength
		return
	}
	credential = append([]byte(nil), rest[2:2+credLen]...)
	mac = append([]byte(nil), rest[2+credLen:]...)
	return
}

// writeReply sends the verified scope commitment: status 1, then the frame
// the client compares byte-for-byte with its request.
func writeReply(w io.Writer, scope overlay.ChannelScope, credential []byte) error {
	var body bytes.Buffer
	body.WriteString(replyMagic)
	encodeScope(scope, &body)
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(credential)))
	body.Write(size[:])
	body.Write(credential)
	if body.Len() > frameMaxBytes-3 {
		return errReplyBound
	}
	out := make([]byte, 0, body.Len()+3)
	out = append(out, 1)
	binary.BigEndian.PutUint16(size[:], uint16(body.Len()))
	out = append(out, size[:]...)
	out = append(out, body.Bytes()...)
	return writeAll(w, out)
}

// readReply parses the responder's commitment. A rejection is one zero byte;
// anything else must be a complete well-formed reply.
func readReply(r io.Reader) (overlay.ChannelScope, []byte, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return overlay.ChannelScope{}, nil, err
	}
	if status[0] == 0 {
		return overlay.ChannelScope{}, nil, overlay.CodeMembershipDenied.Wrap("responder rejected the channel")
	}
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return overlay.ChannelScope{}, nil, err
	}
	total := int(binary.BigEndian.Uint16(head[:]))
	if total < len(replyMagic)+frameFixedBytes+2 || total > frameMaxBytes-3 {
		return overlay.ChannelScope{}, nil, errReplyLength
	}
	body := make([]byte, total)
	if _, err := io.ReadFull(r, body); err != nil {
		return overlay.ChannelScope{}, nil, err
	}
	if !bytes.HasPrefix(body, []byte(replyMagic)) {
		return overlay.ChannelScope{}, nil, errReplyMagic
	}
	scope, err := decodeScope(body[len(replyMagic) : len(replyMagic)+frameFixedBytes])
	if err != nil {
		return overlay.ChannelScope{}, nil, err
	}
	rest := body[len(replyMagic)+frameFixedBytes:]
	credLen := int(binary.BigEndian.Uint16(rest[:2]))
	if len(rest) != 2+credLen {
		return overlay.ChannelScope{}, nil, errReplyCredLength
	}
	return scope, append([]byte(nil), rest[2:]...), nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
