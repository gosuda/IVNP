package sam

import (
	"crypto/subtle"
	"encoding/base64"
)

const samAuthBytes = 32

// authorizedSession resolves an ID only when the caller owns its root or
// presents the per-root capability. The global session map is not authority.
func (s *Server) authorizedSession(connection *serverConnection, id, token string) *samSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session := s.sessions[id]
	if session == nil || session.root == nil {
		return nil
	}
	if connection != nil && connection.root != nil && connection.root == session.root {
		return session
	}
	if len(token) != base64.RawURLEncoding.EncodedLen(samAuthBytes) {
		return nil
	}
	var supplied [samAuthBytes]byte
	n, err := base64.RawURLEncoding.Decode(supplied[:], []byte(token))
	if err != nil || n != samAuthBytes || subtle.ConstantTimeCompare(supplied[:], session.root.auth[:]) != 1 {
		return nil
	}
	return session
}
