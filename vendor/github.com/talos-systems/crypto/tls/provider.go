// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	talosx509 "github.com/talos-systems/crypto/x509"
)

// CertificateProvider describes an interface by which TLS certificates may be managed.
type CertificateProvider interface {
	// GetCA returns the active root CA.
	GetCA() ([]byte, error)

	// GetCertificate returns the current certificate matching the given client request.
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// GetClientCertificate returns the current certificate to present to the server.
	GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// Generator describes an interface to sign the CSR.
type Generator interface {
	Identity(csr *talosx509.CertificateSigningRequest) (ca, crt []byte, err error)
}

//nolint:govet
type certificateProvider struct {
	rw sync.RWMutex

	generator Generator

	ca  []byte
	crt *tls.Certificate

	csrOptions []talosx509.Option
}

// NewRenewingCertificateProvider returns a new CertificateProvider
// which manages and updates its certificates using Generator.
func NewRenewingCertificateProvider(generator Generator, csrOptions ...talosx509.Option) (CertificateProvider, error) {
	provider := &certificateProvider{
		generator:  generator,
		csrOptions: csrOptions,
	}

	ca, cert, err := provider.update()
	if err != nil {
		return nil, fmt.Errorf("failed to create initial certificate: %w", err)
	}

	provider.updateCertificates(ca, cert)

	go provider.manageUpdates(context.TODO()) //nolint:errcheck

	return provider, nil
}

func (p *certificateProvider) update() ([]byte, *tls.Certificate, error) {
	csr, identity, err := talosx509.NewEd25519CSRAndIdentity(p.csrOptions...)
	if err != nil {
		return nil, nil, err
	}

	ca, crt, err := p.generator.Identity(csr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate identity: %w", err)
	}

	identity.Crt = crt

	cert, err := tls.X509KeyPair(identity.Crt, identity.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse cert and key into a TLS Certificate: %w", err)
	}

	return ca, &cert, nil
}

func (p *certificateProvider) GetCA() ([]byte, error) {
	if p == nil {
		return nil, errors.New("no provider")
	}

	p.rw.RLock()
	defer p.rw.RUnlock()

	return p.ca, nil
}

func (p *certificateProvider) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p == nil {
		return nil, errors.New("no provider")
	}

	p.rw.RLock()
	defer p.rw.RUnlock()

	return p.crt, nil
}

func (p *certificateProvider) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return p.GetCertificate(nil)
}

func (p *certificateProvider) updateCertificates(ca []byte, cert *tls.Certificate) {
	p.rw.Lock()
	defer p.rw.Unlock()

	p.ca = ca
	p.crt = cert
}

func (p *certificateProvider) manageUpdates(ctx context.Context) error {
	nextRenewal := talosx509.DefaultCertificateValidityDuration

	for ctx.Err() == nil {
		if c, _ := p.GetCertificate(nil); c != nil { //nolint:errcheck
			if len(c.Certificate) > 0 {
				crt, err := x509.ParseCertificate(c.Certificate[0])

				if err == nil {
					log.Printf("issued certificate with fingerprint %s\n", talosx509.SPKIFingerprint(crt))

					nextRenewal = time.Until(crt.NotAfter) / 2
				} else {
					log.Println("failed to parse current leaf certificate")
				}
			} else {
				log.Println("current leaf certificate not found")
			}
		} else {
			log.Println("certificate not found")
		}

		log.Println("next renewal in", nextRenewal)

		if nextRenewal > talosx509.DefaultCertificateValidityDuration {
			nextRenewal = talosx509.DefaultCertificateValidityDuration
		}

		select {
		case <-time.After(nextRenewal):
		case <-ctx.Done():
			return nil
		}

		ca, cert, err := p.update()
		if err != nil {
			log.Println("failed to renew certificate:", err)

			continue
		}

		p.updateCertificates(ca, cert)
	}

	return errors.New("certificate update manager exited unexpectedly")
}
