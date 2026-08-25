package ssu2

import "crypto/subtle"

// PathValidator tracks one in-flight authenticated SSU2 migration challenge.
type PathValidator struct {
	challenge [16]byte
	length    uint8
	deadline  uint64
	active    bool
}

func (p *PathValidator) Begin(challenge []byte, deadline uint64) bool {
	if len(challenge) < 8 || len(challenge) > len(p.challenge) {
		return false
	}
	copy(p.challenge[:], challenge)
	p.length, p.deadline, p.active = uint8(len(challenge)), deadline, true
	return true
}

func (p *PathValidator) Validate(response []byte, now uint64) bool {
	if !p.active || now > p.deadline || len(response) != int(p.length) {
		return false
	}
	valid := subtle.ConstantTimeCompare(p.challenge[:p.length], response) == 1
	if valid {
		p.active = false
	}
	return valid
}

func (p *PathValidator) Expired(now uint64) bool {
	if p.active && now > p.deadline {
		p.active = false
		return true
	}
	return false
}
