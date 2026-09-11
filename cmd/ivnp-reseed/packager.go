package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"gosuda.org/ivnp/foundation"
)

const (
	su3HeaderLen         = 40
	su3RSASignatureLen   = 512
	su3MinimumVersion    = 16
	su3FileTypeZIP       = 0
	su3ContentTypeReseed = 3
	ivbsMagic            = "IVBS"
	ivbsVersion          = 1
)

var (
	ErrInvalidPrivateKey = errors.New("packager: invalid private key")
	ErrInvalidSignerID   = errors.New("packager: invalid signer ID length")
	ErrMalformedIVBS     = errors.New("packager: malformed IVBS archive")
	ErrInvalidSignature  = errors.New("packager: invalid archive signature")
)

// BuildSU3 builds a signed standard I2P SU3 reseed container containing a ZIP archive of routerInfos.
func BuildSU3(peers []PeerRecord, signerID string, privKey *rsa.PrivateKey, now time.Time) ([]byte, error) {
	if privKey == nil || privKey.N.BitLen() != 4096 {
		return nil, ErrInvalidPrivateKey
	}
	if len(signerID) == 0 || len(signerID) > 255 {
		return nil, ErrInvalidSignerID
	}

	// 1. Build ZIP archive of routerInfos
	var zipBuf bytes.Buffer
	zipWriter := zip.NewWriter(&zipBuf)

	for _, p := range peers {
		b64Hash := base64.RawURLEncoding.EncodeToString(p.Hash[:])
		fileName := fmt.Sprintf("routerInfo-%s.dat", b64Hash)
		w, err := zipWriter.Create(fileName)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(p.Raw); err != nil {
			return nil, err
		}
	}
	if err := zipWriter.Close(); err != nil {
		return nil, err
	}
	zipPayload := zipBuf.Bytes()

	// 2. Format 16-byte version string
	verStr := now.UTC().Format("2006010215040500")
	if len(verStr) < su3MinimumVersion {
		verStr = fmt.Sprintf("%-16s", verStr)
	}
	versionBytes := []byte(verStr[:su3MinimumVersion])
	signerBytes := []byte(signerID)

	// 3. Construct 40-byte SU3 header
	header := make([]byte, su3HeaderLen)
	copy(header[:7], []byte{'I', '2', 'P', 's', 'u', '3', 0})
	header[7] = 0 // file version
	binary.BigEndian.PutUint16(header[8:10], uint16(foundation.SigningRSASHA512_4096))
	binary.BigEndian.PutUint16(header[10:12], su3RSASignatureLen)
	header[13] = byte(len(versionBytes))
	header[15] = byte(len(signerBytes))
	binary.BigEndian.PutUint64(header[16:24], uint64(len(zipPayload)))
	header[25] = su3FileTypeZIP
	header[27] = su3ContentTypeReseed

	// 4. Concatenate signed portion: Header + Version + Signer + Content
	signedPortion := bytes.NewBuffer(make([]byte, 0, su3HeaderLen+len(versionBytes)+len(signerBytes)+len(zipPayload)+su3RSASignatureLen))
	signedPortion.Write(header)
	signedPortion.Write(versionBytes)
	signedPortion.Write(signerBytes)
	signedPortion.Write(zipPayload)

	// 5. Sign with RSA-4096 PKCS#1 v1.5 (NONEwithRSA style matching Java I2P / IVNP)
	digest := sha512.Sum512(signedPortion.Bytes())
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.Hash(0), digest[:])
	if err != nil {
		return nil, fmt.Errorf("packager: rsa sign: %w", err)
	}

	signedPortion.Write(signature)
	return signedPortion.Bytes(), nil
}

// BuildIVBS packages peers into IVNP's zero-allocation binary format signed with Ed25519.
func BuildIVBS(peers []PeerRecord, networkID uint8, privKey ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}

	var buf bytes.Buffer
	// Header: Magic(4) + Version(2) + NetworkID(1) + Flags(1) + Timestamp(8) + Count(2) = 18 bytes
	buf.WriteString(ivbsMagic)
	var numBuf [8]byte
	binary.BigEndian.PutUint16(numBuf[:2], ivbsVersion)
	buf.Write(numBuf[:2])
	buf.WriteByte(networkID)
	buf.WriteByte(0) // Flags: uncompressed
	binary.BigEndian.PutUint64(numBuf[:8], uint64(now.UnixMilli()))
	buf.Write(numBuf[:8])
	binary.BigEndian.PutUint16(numBuf[:2], uint16(len(peers)))
	buf.Write(numBuf[:2])

	// RouterInfo entries
	for _, p := range peers {
		binary.BigEndian.PutUint16(numBuf[:2], uint16(len(p.Raw)))
		buf.Write(numBuf[:2])
		buf.Write(p.Raw)
	}

	// Sign payload with Ed25519
	payload := buf.Bytes()
	signature := ed25519.Sign(privKey, payload)
	buf.Write(signature)

	return buf.Bytes(), nil
}

// ParseIVBS parses and verifies an IVBS archive using the server's Ed25519 public key.
func ParseIVBS(data []byte, pubKey ed25519.PublicKey) ([]foundation.NetworkDatabaseRouterInfo, error) {
	const headerLen = 18
	const sigLen = ed25519.SignatureSize
	if len(data) < headerLen+sigLen {
		return nil, ErrMalformedIVBS
	}
	if string(data[:4]) != ivbsMagic {
		return nil, ErrMalformedIVBS
	}

	payloadLen := len(data) - sigLen
	payload := data[:payloadLen]
	signature := data[payloadLen:]

	if !ed25519.Verify(pubKey, payload, signature) {
		return nil, ErrInvalidSignature
	}

	count := int(binary.BigEndian.Uint16(payload[16:18]))
	offset := headerLen
	results := make([]foundation.NetworkDatabaseRouterInfo, 0, count)

	for i := 0; i < count; i++ {
		if offset+2 > payloadLen {
			return nil, ErrMalformedIVBS
		}
		itemLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		if offset+itemLen > payloadLen {
			return nil, ErrMalformedIVBS
		}
		raw := payload[offset : offset+itemLen]
		offset += itemLen

		info, err := foundation.NetworkDatabaseParseRouterInfo(raw)
		if err != nil {
			return nil, err
		}
		results = append(results, info)
	}

	return results, nil
}
