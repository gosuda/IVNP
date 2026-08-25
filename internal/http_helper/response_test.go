package httphelper

import "testing"

func TestParseResponse(t *testing.T) {
	response, err := ParseResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody"), 8)
	if err != nil || response.StatusCode != 200 || string(response.Body) != "body" {
		t.Fatalf("response=%#v err=%v", response, err)
	}
	if _, err := ParseResponse([]byte("HTTP/1.1 200 OK\r\n\r\n123"), 2); err != ErrResponse {
		t.Fatalf("body bound=%v", err)
	}
}
