// Package wire provides zero-allocation binary parsing and serialization primitives for I2P wire formats.
package wire

import (
	"encoding/binary"
	"errors"
)

var (
	ErrShortBuffer = errors.New("wire: truncated input")
	ErrLargeField  = errors.New("wire: invalid field length")
)

// Cursor provides sequential, zero-allocation reading over a byte slice.
// Returned slices point directly into the underlying buffer.
type Cursor struct {
	buf []byte
	off int
}

// NewCursor creates a cursor positioned at the start of buf.
func NewCursor(buf []byte) Cursor { return Cursor{buf: buf} }

func (c Cursor) Offset() int    { return c.off }
func (c Cursor) Remaining() int { return len(c.buf) - c.off }
func (c Cursor) Done() bool     { return c.off == len(c.buf) }
func (c Cursor) Bytes() []byte  { return c.buf[c.off:] }

// ReadU8 reads a single byte.
func (c *Cursor) ReadU8() (uint8, error) {
	if c.off == len(c.buf) {
		return 0, ErrShortBuffer
	}
	v := c.buf[c.off]
	c.off++
	return v, nil
}

// ReadU16 reads a 16-bit big-endian integer.
func (c *Cursor) ReadU16() (uint16, error) {
	b, err := c.ReadBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

// ReadU32 reads a 32-bit big-endian integer.
func (c *Cursor) ReadU32() (uint32, error) {
	b, err := c.ReadBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// ReadU64 reads a 64-bit big-endian integer.
func (c *Cursor) ReadU64() (uint64, error) {
	b, err := c.ReadBytes(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// ReadBytes reads the next n bytes without copying.
func (c *Cursor) ReadBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrLargeField
	}
	if n > len(c.buf)-c.off {
		return nil, ErrShortBuffer
	}
	start := c.off
	c.off += n
	return c.buf[start:c.off], nil
}

// Skip advances the cursor by n bytes.
func (c *Cursor) Skip(n int) error {
	_, err := c.ReadBytes(n)
	return err
}

// Writer writes structured data into a fixed-capacity byte slice without allocations.
type Writer struct {
	buf []byte
	off int
}

// NewWriter returns a writer writing into dst.
func NewWriter(dst []byte) Writer { return Writer{buf: dst} }

func (w Writer) Offset() int    { return w.off }
func (w Writer) Available() int { return len(w.buf) - w.off }
func (w Writer) Bytes() []byte  { return w.buf[:w.off] }

// PutU8 writes a single byte.
func (w *Writer) PutU8(v uint8) error {
	if w.off == len(w.buf) {
		return ErrShortBuffer
	}
	w.buf[w.off] = v
	w.off++
	return nil
}

// PutU16 writes a 16-bit big-endian integer.
func (w *Writer) PutU16(v uint16) error {
	b, err := w.Reserve(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(b, v)
	return nil
}

// PutU32 writes a 32-bit big-endian integer.
func (w *Writer) PutU32(v uint32) error {
	b, err := w.Reserve(4)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint32(b, v)
	return nil
}

// PutU64 writes a 64-bit big-endian integer.
func (w *Writer) PutU64(v uint64) error {
	b, err := w.Reserve(8)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint64(b, v)
	return nil
}

// Put copies src into the writer.
func (w *Writer) Put(src []byte) error {
	b, err := w.Reserve(len(src))
	if err != nil {
		return err
	}
	copy(b, src)
	return nil
}

// Reserve advances the write offset by n bytes and returns the writable slice.
func (w *Writer) Reserve(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrLargeField
	}
	if n > len(w.buf)-w.off {
		return nil, ErrShortBuffer
	}
	start := w.off
	w.off += n
	return w.buf[start:w.off], nil
}
