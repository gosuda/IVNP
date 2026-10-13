package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	webUISSECookieName     = "ivnp-sse"
	webUISSECookieLifetime = 2 * time.Minute
)

// issueSSECookie grants browser EventSource access without putting the
// reusable administrator token in a URL. The cookie is valid for SSE only.
func (s *WebUIServer) issueSSECookie(w http.ResponseWriter, r *http.Request, now time.Time) {
	expiry := strconv.FormatInt(now.Add(webUISSECookieLifetime).Unix(), 10)
	mac := hmac.New(sha256.New, s.sseCookieKey[:])
	_, _ = mac.Write([]byte(expiry))
	http.SetCookie(w, &http.Cookie{
		Name:     webUISSECookieName,
		Value:    expiry + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
		Path:     "/api/events",
		MaxAge:   int(webUISSECookieLifetime / time.Second),
		Secure:   r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *WebUIServer) sseCookieAuthorized(r *http.Request, now time.Time) bool {
	cookie, err := r.Cookie(webUISSECookieName)
	if err != nil {
		return false
	}
	expiryText, signatureText, ok := strings.Cut(cookie.Value, ".")
	if !ok {
		return false
	}
	expiry, err := strconv.ParseInt(expiryText, 10, 64)
	if err != nil || expiry <= now.Unix() {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || len(signature) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, s.sseCookieKey[:])
	_, _ = mac.Write([]byte(expiryText))
	return hmac.Equal(signature, mac.Sum(nil))
}
