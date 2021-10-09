// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Fingerprint represents SPKI certificate fingerprint.
type Fingerprint []byte

func (f Fingerprint) String() string {
	return base64.StdEncoding.EncodeToString(f)
}

// Equal checks is Fingerprints match.
func (f Fingerprint) Equal(other Fingerprint) bool {
	return bytes.Equal(f, other)
}

// ParseFingerprint parses string representation of the fingerprint.
func ParseFingerprint(s string) (Fingerprint, error) {
	return base64.StdEncoding.DecodeString(s)
}

// SPKIFingerprintFromPEM computes SPKI certificate fingerprint from PEM representation of the x509 certificate.
func SPKIFingerprintFromPEM(certPEM []byte) (Fingerprint, error) {
	block, _ := pem.Decode(certPEM)

	if block == nil {
		return nil, fmt.Errorf("failed parsing PEM block")
	}

	return SPKIFingerprintFromDER(block.Bytes)
}

// SPKIFingerprintFromDER computes SPKI certificate fingerprint from ASN.1 DER representation of the x509 certificate.
func SPKIFingerprintFromDER(certDER []byte) (Fingerprint, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return SPKIFingerprint(cert), nil
}

// SPKIFingerprint computes SPKI certificate fingerprint.
func SPKIFingerprint(cert *x509.Certificate) Fingerprint {
	hash := sha256.New()
	hash.Write(cert.RawSubjectPublicKeyInfo)

	return Fingerprint(hash.Sum(nil))
}

// MatchSPKIFingerprints can be injected as tls.Config.VerifyConnection handler to deny connection if peer certificates don't match the fingerprints.
func MatchSPKIFingerprints(fingerprints ...Fingerprint) func(tls.ConnectionState) error {
	return func(connState tls.ConnectionState) error {
		if len(connState.PeerCertificates) == 0 {
			return fmt.Errorf("no peer certificates found")
		}

		peerCert := connState.PeerCertificates[0] // leaf certificate

		matched := false

		for _, fingerprint := range fingerprints {
			if fingerprint.Equal(SPKIFingerprint(peerCert)) {
				matched = true

				break
			}
		}

		if !matched {
			fingerpintStrings := make([]string, len(fingerprints))

			for i := range fingerprints {
				fingerpintStrings[i] = fingerprints[i].String()
			}

			return fmt.Errorf("leaf peer certificate doesn't match the provided fingerprints: %v", fingerpintStrings)
		}

		return nil
	}
}
