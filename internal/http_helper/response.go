// Package httphelper provides bounded HTTP response parsing for router utilities.
package httphelper

import (
	"bytes"
	"errors"
	"strconv"
)

var ErrResponse = errors.New("httpx: malformed response")

type Response struct {
	StatusCode int
	Headers    []byte
	Body       []byte
}

func ParseResponse(src []byte, maxBody int) (Response, error) {
	end := bytes.Index(src, []byte("\r\n\r\n"))
	if end < 0 {
		return Response{}, ErrResponse
	}
	lines := bytes.Split(src[:end], []byte("\r\n"))
	if len(lines) == 0 || len(lines[0]) < 12 || !bytes.HasPrefix(lines[0], []byte("HTTP/")) {
		return Response{}, ErrResponse
	}
	fields := bytes.Fields(lines[0])
	if len(fields) < 2 {
		return Response{}, ErrResponse
	}
	status, err := strconv.Atoi(string(fields[1]))
	if err != nil || status < 100 || status > 599 {
		return Response{}, ErrResponse
	}
	body := src[end+4:]
	if maxBody >= 0 && len(body) > maxBody {
		return Response{}, ErrResponse
	}
	return Response{StatusCode: status, Headers: src[len(lines[0])+2 : end], Body: body}, nil
}
