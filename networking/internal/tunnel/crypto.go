package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const LayerPayloadSize = 1024

var ErrLayerSize = errors.New("tunnel: layer payload must be 1024 bytes")

// LayerCipher implements an immutable i2pd double-IV tunnel transform. AES
// block schedules are constructed once at circuit installation, never in the
// packet hot path.
type LayerCipher struct {
	layer, ivKey        [32]byte
	layerBlock, ivBlock cipher.Block
	encrypt             bool
}

func NewLayerEncryptor(layer, ivKey []byte) (LayerCipher, error) { return newLayer(layer, ivKey, true) }
func NewLayerDecryptor(layer, ivKey []byte) (LayerCipher, error) {
	return newLayer(layer, ivKey, false)
}
func newLayer(layer, ivKey []byte, encrypt bool) (LayerCipher, error) {
	if len(layer) != 32 || len(ivKey) != 32 {
		return LayerCipher{}, ErrLayerSize
	}
	var c LayerCipher
	copy(c.layer[:], layer)
	copy(c.ivKey[:], ivKey)
	var err error
	c.layerBlock, err = aes.NewCipher(c.layer[:])
	if err != nil {
		return LayerCipher{}, err
	}
	c.ivBlock, err = aes.NewCipher(c.ivKey[:])
	if err != nil {
		return LayerCipher{}, err
	}
	c.encrypt = encrypt
	return c, nil
}
func (c *LayerCipher) Transform(dst, src []byte) error {
	if len(dst) < LayerPayloadSize || len(src) < LayerPayloadSize {
		return ErrLayerSize
	}
	if c.layerBlock == nil || c.ivBlock == nil {
		return ErrLayerSize
	}
	layer, ivc := c.layerBlock, c.ivBlock
	var iv [aes.BlockSize]byte
	if c.encrypt {
		ivc.Encrypt(iv[:], src[:16])
		cbcEncrypt(layer, dst[16:1024], src[16:1024], iv[:])
		ivc.Encrypt(dst[:16], iv[:])
	} else {
		ivc.Decrypt(iv[:], src[:16])
		cbcDecrypt(layer, dst[16:1024], src[16:1024], iv[:])
		ivc.Decrypt(dst[:16], iv[:])
	}
	return nil
}
func cbcEncrypt(block cipher.Block, dst, src, iv []byte) {
	var prev [aes.BlockSize]byte
	copy(prev[:], iv)
	for off := 0; off < len(src); off += aes.BlockSize {
		for i := range aes.BlockSize {
			dst[off+i] = src[off+i] ^ prev[i]
		}
		block.Encrypt(dst[off:off+aes.BlockSize], dst[off:off+aes.BlockSize])
		copy(prev[:], dst[off:off+aes.BlockSize])
	}
}
func cbcDecrypt(block cipher.Block, dst, src, iv []byte) {
	var prev, cur [aes.BlockSize]byte
	copy(prev[:], iv)
	for off := 0; off < len(src); off += aes.BlockSize {
		copy(cur[:], src[off:off+aes.BlockSize])
		block.Decrypt(dst[off:off+aes.BlockSize], src[off:off+aes.BlockSize])
		for i := range aes.BlockSize {
			dst[off+i] ^= prev[i]
		}
		prev = cur
	}
}
