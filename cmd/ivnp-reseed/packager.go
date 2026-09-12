package main

import (
	"archive/zip"
	"bytes"
	"crypto"
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
)

var (
	ErrInvalidPrivateKey = errors.New("packager: invalid private key")
	ErrInvalidSignerID   = errors.New("packager: invalid signer ID length")
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
