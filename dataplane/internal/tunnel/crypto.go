package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"sync"
)

const LayerPayloadSize = 1024

var ErrLayerSize = errors.New("tunnel: layer payload must be 1024 bytes")

// LayerCipher implements an immutable i2pd double-IV tunnel transform. AES
// block schedules are constructed once at circuit installation, never in the
// packet hot path.
type LayerCipher struct {
	layerBlock, ivBlock cipher.Block
	modePool            *cbcModePool
	encrypt             bool
}

type reusableCBCMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

type reusableCBCState struct {
	mode reusableCBCMode
	iv   [aes.BlockSize]byte
}

type cbcModePool struct {
	block   cipher.Block
	encrypt bool
	modes   sync.Pool
}

func newCBCModePool(block cipher.Block, encrypt bool) *cbcModePool {
	pool := &cbcModePool{block: block, encrypt: encrypt}
	pool.modes.New = func() any { return pool.newMode() }
	pool.modes.Put(pool.newMode())
	return pool
}

func (p *cbcModePool) newMode() *reusableCBCState {
	var iv [aes.BlockSize]byte
	var mode cipher.BlockMode
	if p.encrypt {
		mode = cipher.NewCBCEncrypter(p.block, iv[:])
	} else {
		mode = cipher.NewCBCDecrypter(p.block, iv[:])
	}
	return &reusableCBCState{mode: mode.(reusableCBCMode)}
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
	// Do not retain a second raw-key copy beside the AES schedules.
	var err error
	c.layerBlock, err = aes.NewCipher(layer)
	if err != nil {
		return LayerCipher{}, err
	}
	c.ivBlock, err = aes.NewCipher(ivKey)
	if err != nil {
		return LayerCipher{}, err
	}
	c.modePool = newCBCModePool(c.layerBlock, encrypt)
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
	layerMode, ivc := c.modePool, c.ivBlock
	state := layerMode.modes.Get().(*reusableCBCState)
	if c.encrypt {
		ivc.Encrypt(state.iv[:], src[:16])
		state.mode.SetIV(state.iv[:])
		state.mode.CryptBlocks(dst[16:1024], src[16:1024])
		ivc.Encrypt(dst[:16], state.iv[:])
	} else {
		ivc.Decrypt(state.iv[:], src[:16])
		state.mode.SetIV(state.iv[:])
		state.mode.CryptBlocks(dst[16:1024], src[16:1024])
		ivc.Decrypt(dst[:16], state.iv[:])
	}
	layerMode.modes.Put(state)
	return nil
}
