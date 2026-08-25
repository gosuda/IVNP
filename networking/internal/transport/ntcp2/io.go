package ntcp2

import (
	"io"
	"math"

	"gosuda.org/ivnp/internal/packet"
	"gosuda.org/ivnp/internal/wire"
)

// WriteFrame encrypts and writes one complete NTCP2 data frame. It owns only a
// pooled temporary frame; the Direction remains single-goroutine-owned.
func (d *Direction) WriteFrame(writer io.Writer, plaintext []byte) error {
	if len(plaintext) > MaxPlaintextFrame {
		return ErrFrameTooLarge
	}
	frameLen := len(plaintext) + FrameTagLen
	frame, ok := packet.Acquire(FrameLengthLen, frameLen)
	if !ok {
		return ErrFrameTooLarge
	}
	defer frame.Release()
	if _, ok = frame.Append(frameLen); !ok {
		return ErrFrameLength
	}
	if _, ok = frame.Push(FrameLengthLen); !ok {
		return ErrFrameLength
	}
	encoded, ok := frame.Bytes()
	if !ok {
		return ErrFrameLength
	}
	if _, err := d.SealTo(encoded, plaintext); err != nil {
		return err
	}
	for encoded, ok := frame.Bytes(); ok && len(encoded) > 0; {
		n, err := writer.Write(encoded)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		encoded = encoded[n:]
	}
	return nil
}

// ReadFrame reads, authenticates, and decrypts exactly one NTCP2 data frame
// into dst. The frame length is decoded once, so SipHash state cannot desync.
func (d *Direction) ReadFrame(reader io.Reader, dst []byte) ([]byte, error) {
	var header [FrameLengthLen]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	frameLen := int(uint16(header[0])<<8 | uint16(header[1]) ^ d.sip.nextMask())
	if frameLen < MinEncryptedFrame || frameLen > MaxEncryptedFrame {
		return nil, ErrFrameLength
	}
	if len(dst) < frameLen-FrameTagLen {
		return nil, wire.ErrShortBuffer
	}
	if d.nonce >= math.MaxUint64-1 {
		return nil, ErrNonceExhausted
	}
	frame, ok := packet.Acquire(0, frameLen)
	if !ok {
		return nil, ErrFrameLength
	}
	defer frame.Release()
	encrypted, ok := frame.Append(frameLen)
	if !ok {
		return nil, ErrFrameLength
	}
	if _, err := io.ReadFull(reader, encrypted); err != nil {
		return nil, err
	}
	binaryNonce := d.nonceBuf[:]
	for i := range binaryNonce {
		binaryNonce[i] = 0
	}
	for i := range 8 {
		binaryNonce[4+i] = byte(d.nonce >> (8 * i))
	}
	encrypted, ok = frame.Bytes()
	if !ok {
		return nil, ErrFrameLength
	}
	plaintext, err := d.cipher.OpenTo(dst, binaryNonce, encrypted, nil)
	if err != nil {
		return nil, err
	}
	d.nonce++
	return plaintext, nil
}
