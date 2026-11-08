package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	errNoSignature  = errors.New("missing signature headers")
	errBadAlg       = errors.New("unsupported signature algorithm")
	errBadTimestamp = errors.New("timestamp outside allowed window")
	errBadSignature = errors.New("signature mismatch")
)

// parsePublicKey приймає сертифікат X.509, PKIX "PUBLIC KEY" або PKCS#1 "RSA PUBLIC KEY".
func parsePublicKey(data []byte) (*rsa.PublicKey, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no RSA key found in PEM")
		}
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			if k, ok := c.PublicKey.(*rsa.PublicKey); ok {
				return k, nil
			}
			return nil, errors.New("certificate key is not RSA")
		case "PUBLIC KEY":
			k, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			if rk, ok := k.(*rsa.PublicKey); ok {
				return rk, nil
			}
			return nil, errors.New("public key is not RSA")
		case "RSA PUBLIC KEY":
			return x509.ParsePKCS1PublicKey(block.Bytes)
		}
	}
}

const minKeyBits = 2048

func checkKey(k *rsa.PublicKey) error {
	if k == nil {
		return errors.New("no key")
	}
	if k.N.BitLen() < minKeyBits {
		return fmt.Errorf("RSA key too short: %d bit (need >= %d)", k.N.BitLen(), minKeyBits)
	}
	return nil
}

// keyFingerprint — SHA-256 від DER (PKIX) публічного ключа, перші 16 байт.
func keyFingerprint(k *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return "?"
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:16])
}

// Verifier перевіряє підпис webhook: RSA PKCS#1 v1.5 + SHA-256 над "{timestamp}.{raw_body}".
type Verifier struct {
	mu        sync.RWMutex
	key       *rsa.PublicKey
	maxSkew   time.Duration
	reload    func() (*rsa.PublicKey, error) // nil, якщо ключ лише з файлу
	lastTry   time.Time
	reloadGap time.Duration
	now       func() time.Time
}

func NewVerifier(key *rsa.PublicKey, maxSkew time.Duration, reload func() (*rsa.PublicKey, error)) *Verifier {
	return &Verifier{key: key, maxSkew: maxSkew, reload: reload, reloadGap: 5 * time.Minute, now: time.Now}
}

// SetKey встановлює ключ (фонове завантаження на старті).
func (v *Verifier) SetKey(k *rsa.PublicKey) error {
	if err := checkKey(k); err != nil {
		return err
	}
	v.mu.Lock()
	v.key = k
	v.mu.Unlock()
	return nil
}

func (v *Verifier) HasKey() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.key != nil
}

func (v *Verifier) check(key *rsa.PublicKey, sig []byte, ts string, body []byte) error {
	h := sha256.New()
	h.Write([]byte(ts))
	h.Write([]byte{'.'})
	h.Write(body)
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, h.Sum(nil), sig) != nil {
		return errBadSignature
	}
	return nil
}

func (v *Verifier) Verify(hdr http.Header, body []byte) error {
	sigB64 := strings.TrimSpace(hdr.Get("X-Webhook-Signature"))
	ts := strings.TrimSpace(hdr.Get("X-Webhook-Timestamp"))
	if sigB64 == "" || ts == "" {
		return errNoSignature
	}
	if alg := strings.ToLower(strings.TrimSpace(hdr.Get("X-Webhook-Signature-Alg"))); alg != "" && alg != "rsa-sha256" {
		return errBadAlg
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errBadTimestamp
	}
	if d := v.now().Sub(time.Unix(sec, 0)); d > v.maxSkew || d < -v.maxSkew {
		return errBadTimestamp
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("%w: bad base64", errBadSignature)
	}
	v.mu.RLock()
	key := v.key
	v.mu.RUnlock()
	if key != nil && v.check(key, sig, ts, body) == nil {
		return nil
	}
	// Можлива ротація ключа на боці ukrainealarm: пробуємо перечитати, не частіше ніж раз на reloadGap.
	if nk := v.tryReload(); nk != nil && v.check(nk, sig, ts, body) == nil {
		return nil
	}
	return errBadSignature
}

func (v *Verifier) tryReload() *rsa.PublicKey {
	if v.reload == nil {
		return nil
	}
	v.mu.Lock()
	if v.now().Sub(v.lastTry) < v.reloadGap {
		v.mu.Unlock()
		return nil
	}
	v.lastTry = v.now()
	v.mu.Unlock()
	k, err := v.reload()
	if err == nil {
		err = checkKey(k)
	}
	if err != nil {
		logf("public key reload failed: %v", err)
		return nil
	}
	v.mu.Lock()
	old := v.key
	v.key = k
	v.mu.Unlock()
	if old == nil || old.N.Cmp(k.N) != 0 || old.E != k.E {
		logf("webhook public key changed: sha256 %s", keyFingerprint(k))
	}
	return k
}
