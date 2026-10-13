package frontend

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
)

var errHTTPResponseHeadersTooLarge = errors.New("upstream HTTP response headers exceed configured limit")

// readBoundedHTTPResponse checks the complete status line and headers before parsing.
// maxHeaderBytes must be positive. The returned reader retains buffered tunnel bytes.
func readBoundedHTTPResponse(upstream *bufio.Reader, request *http.Request, maxHeaderBytes int) (*http.Response, *bufio.Reader, error) {
	header := make([]byte, 0, min(maxHeaderBytes, 4096))
	lineLength := 0
	for {
		fragment, err := upstream.ReadSlice('\n')
		if len(fragment) > maxHeaderBytes-len(header) {
			return nil, nil, errHTTPResponseHeadersTooLarge
		}
		header = append(header, fragment...)
		lineLength += len(fragment)
		if err == nil {
			if lineLength == 1 || (lineLength == 2 && header[len(header)-2] == '\r') {
				buffered := bufio.NewReader(io.MultiReader(bytes.NewReader(header), upstream))
				response, parseErr := http.ReadResponse(buffered, request)
				if parseErr != nil {
					return nil, nil, parseErr
				}
				return response, buffered, nil
			}
			lineLength = 0
		} else if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, nil, err
		}
		if len(header) == maxHeaderBytes {
			return nil, nil, errHTTPResponseHeadersTooLarge
		}
	}
}
