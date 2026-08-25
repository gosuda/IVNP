package clientapi

import (
	"net/http"

	"gosuda.org/ivnp/internal/ingress"
)

func recoverHTTP(reporter ingress.Reporter, handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				_ = ingress.Report(recovered, reporter, ingress.BoundaryHTTPHandler, nil)
				http.Error(writer, "internal server error", http.StatusInternalServerError)
			}
		}()
		handler(writer, request)
	}
}
