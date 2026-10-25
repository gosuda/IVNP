package ntcp2

import (
	"net"
	"sync"
)

// Session manages an established NTCP2 connection with directional encryption states.
//
// Lock hierarchy: lifecycle -> writeMu.
type Session struct {
	conn net.Conn
	// +checklocks:lifecycle
	// +checklocks:writeMu
	send *Direction
	// +checklocks:lifecycle
	receive   *Direction
	writeMu   sync.Mutex
	lifecycle sync.RWMutex
	closeOnce sync.Once
}

func NewSession(conn net.Conn, send, receive *Direction) *Session {
	return &Session{conn: conn, send: send, receive: receive}
}
func (s *Session) Conn() net.Conn { return s.conn }

// +checklocksexclude:s.lifecycle
// +checklocksexclude:s.writeMu
func (s *Session) Write(plaintext []byte) error {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.send == nil {
		return net.ErrClosed
	}
	return s.send.WriteFrame(s.conn, plaintext)
}

// +checklocksexclude:s.lifecycle
// +checklocksexclude:s.writeMu
func (s *Session) Read(dst []byte) ([]byte, error) {
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	if s.receive == nil {
		return nil, net.ErrClosed
	}
	return s.receive.ReadFrame(s.conn, dst)
}

// +checklocksexclude:s.lifecycle
// +checklocksexclude:s.writeMu
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.conn.Close()
		s.lifecycle.Lock()
		s.writeMu.Lock()
		if s.send != nil {
			s.send.ReleaseSensitive()
			s.send = nil
		}
		s.writeMu.Unlock()
		if s.receive != nil {
			s.receive.ReleaseSensitive()
			s.receive = nil
		}
		s.lifecycle.Unlock()
	})
	return err
}
