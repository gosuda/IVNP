package ssu2

import (
	"encoding/binary"

	"gosuda.org/ivnp/internal/wire"
)

const (
	BlockDateTime         = 0
	BlockOptions          = 1
	BlockRouterInfo       = 2
	BlockI2NP             = 3
	BlockFirstFragment    = 4
	BlockFollowOnFragment = 5
	BlockTermination      = 6
	BlockRelayRequest     = 7
	BlockRelayResponse    = 8
	BlockRelayIntro       = 9
	BlockPeerTest         = 10
	BlockNextNonce        = 11
	BlockACK              = 12
	BlockAddress          = 13
	BlockIntroKey         = 14
	BlockRelayTagRequest  = 15
	BlockRelayTag         = 16
	BlockNewToken         = 17
	BlockPathChallenge    = 18
	BlockPathResponse     = 19
	BlockFirstPacket      = 20
	BlockPadding          = 254
)

// Block is a zero-copy SSU2 payload block.
type Block struct {
	Type uint8
	Data []byte
}

type BlockIterator struct {
	rest               []byte
	terminated, padded bool
}

func NewBlockIterator(payload []byte) BlockIterator { return BlockIterator{rest: payload} }

func (it *BlockIterator) Next() (Block, bool, error) {
	if len(it.rest) == 0 {
		return Block{}, false, nil
	}
	if it.padded || (it.terminated && it.rest[0] != BlockPadding) {
		return Block{}, false, ErrPacketLength
	}
	if len(it.rest) < 3 {
		return Block{}, false, wire.ErrShortBuffer
	}
	n := int(binary.BigEndian.Uint16(it.rest[1:3]))
	if n > len(it.rest)-3 {
		return Block{}, false, wire.ErrShortBuffer
	}
	block := Block{Type: it.rest[0], Data: it.rest[3 : 3+n]}
	it.rest = it.rest[3+n:]
	if err := validateBlock(block); err != nil {
		return Block{}, false, err
	}
	if block.Type == BlockPadding {
		it.padded = true
	}
	if block.Type == BlockTermination {
		it.terminated = true
	}
	if it.padded && len(it.rest) != 0 {
		return Block{}, false, ErrPacketLength
	}
	return block, true, nil
}

func validateBlock(block Block) error {
	switch block.Type {
	case BlockDateTime:
		if len(block.Data) != 4 {
			return ErrPacketLength
		}
	case BlockOptions:
		if len(block.Data) < 12 {
			return ErrPacketLength
		}
	case BlockRouterInfo:
		if len(block.Data) < 2 || block.Data[0]&0xfc != 0 || block.Data[1] != 1 {
			return ErrPacketLength
		}
	case BlockI2NP:
		if len(block.Data) < 9 {
			return ErrPacketLength
		}
	case BlockFirstFragment:
		if len(block.Data) <= 9 {
			return ErrPacketLength
		}
	case BlockFollowOnFragment:
		if len(block.Data) <= 5 || block.Data[0]>>1 == 0 {
			return ErrPacketLength
		}
	case BlockTermination:
		if len(block.Data) < 9 {
			return ErrPacketLength
		}
	case BlockAddress:
		if len(block.Data) != 6 && len(block.Data) != 18 {
			return ErrPacketLength
		}
	case BlockRelayRequest:
		if _, err := ParseRelayRequestBlock(block.Data); err != nil {
			return err
		}
	case BlockRelayResponse:
		if _, err := ParseRelayResponseBlock(block.Data); err != nil {
			return err
		}
	case BlockRelayIntro:
		if _, err := ParseRelayIntroBlock(block.Data); err != nil {
			return err
		}
	case BlockPeerTest:
		if _, err := ParsePeerTestBlock(block.Data); err != nil {
			return err
		}
	case BlockRelayTagRequest:
		if _, err := ParseRelayTagRequestBlock(block.Data); err != nil {
			return err
		}
	case BlockRelayTag:
		if _, err := ParseRelayTagBlock(block.Data); err != nil {
			return err
		}
	case BlockNewToken:
		if _, err := ParseNewTokenBlock(block.Data); err != nil {
			return err
		}
	case BlockPathChallenge:
		if _, err := ParsePathChallengeBlock(block.Data); err != nil {
			return err
		}
	case BlockPathResponse:
		if _, err := ParsePathResponseBlock(block.Data); err != nil {
			return err
		}
	}
	return nil
}
