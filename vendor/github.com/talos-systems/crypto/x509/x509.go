// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package x509 provides wrapper around standard crypto/* packages.
package x509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"strings"
	"time"
)

// CertificateAuthority represents a CA.
type CertificateAuthority struct {
	Crt    *x509.Certificate
	CrtPEM []byte
	Key    interface{}
	KeyPEM []byte
}

// Ed25519Key represents an Ed25519 key.
type Ed25519Key struct {
	PublicKey     ed25519.PublicKey
	PrivateKey    ed25519.PrivateKey
	PublicKeyPEM  []byte
	PrivateKeyPEM []byte
}

// RSAKey represents an RSA key.
type RSAKey struct {
	keyRSA       *rsa.PrivateKey
	KeyPEM       []byte
	PublicKeyPEM []byte
}

// ECDSAKey represents an ECDSA key.
type ECDSAKey struct {
	keyEC        *ecdsa.PrivateKey
	KeyPEM       []byte
	PublicKeyPEM []byte
}

// Key is a common interface implemented by RSAKey, ECDSAKey and Ed25519Key.
type Key interface {
	GetPrivateKeyPEM() []byte
	GetPublicKeyPEM() []byte
}

// Certificate represents an X.509 certificate.
type Certificate struct {
	X509Certificate    *x509.Certificate
	X509CertificatePEM []byte
}

// CertificateSigningRequest represents a CSR.
type CertificateSigningRequest struct {
	X509CertificateRequest    *x509.CertificateRequest
	X509CertificateRequestPEM []byte
}

// KeyPair represents a certificate and key pair.
type KeyPair struct {
	*tls.Certificate

	CrtPEM []byte
	KeyPEM []byte
}

// PEMEncodedCertificateAndKey represents a PEM encoded certificate and
// private key pair.
type PEMEncodedCertificateAndKey struct {
	Crt []byte
	Key []byte
}

// PEMEncodedKey represents a PEM encoded private key.
type PEMEncodedKey struct {
	Key []byte
}

// Options is the functional options struct.
//
//nolint:govet
type Options struct {
	CommonName         string
	Organizations      []string
	SignatureAlgorithm x509.SignatureAlgorithm
	IPAddresses        []net.IP
	DNSNames           []string
	Bits               int
	NotAfter           time.Time
	NotBefore          time.Time
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage
}

// Option is the functional option func.
type Option func(*Options)

// CommonName sets the common name of the certificate.
func CommonName(o string) Option {
	return func(opts *Options) {
		opts.CommonName = o
	}
}

// Organization sets the subject organizations of the certificate.
func Organization(o ...string) Option {
	return func(opts *Options) {
		opts.Organizations = o
	}
}

// SignatureAlgorithm sets the hash algorithm used to sign the SSL certificate.
func SignatureAlgorithm(o x509.SignatureAlgorithm) Option {
	return func(opts *Options) {
		opts.SignatureAlgorithm = o
	}
}

// IPAddresses sets the value for the IP addresses in Subject Alternate Name of
// the certificate.
func IPAddresses(o []net.IP) Option {
	return func(opts *Options) {
		opts.IPAddresses = o
	}
}

// DNSNames sets the value for the DNS Names in Subject Alternate Name of
// the certificate.
func DNSNames(o []string) Option {
	return func(opts *Options) {
		opts.DNSNames = o
	}
}

// Bits sets the bit size of the RSA key pair.
func Bits(o int) Option {
	return func(opts *Options) {
		opts.Bits = o
	}
}

// KeyUsage sets the bitmap of the KeyUsage* constants.
func KeyUsage(o x509.KeyUsage) Option {
	return func(opts *Options) {
		opts.KeyUsage = o
	}
}

// ExtKeyUsage sets the ExtKeyUsage* constants.
func ExtKeyUsage(o []x509.ExtKeyUsage) Option {
	return func(opts *Options) {
		opts.ExtKeyUsage = o
	}
}

// RSA sets a flag for indicating that the requested operation should be
// performed under the context of RSA instead of the default Ed25519.
func RSA(o bool) Option {
	return func(opts *Options) {
		if o {
			opts.SignatureAlgorithm = x509.SHA512WithRSA
		}
	}
}

// ECDSA sets a flag for indicating that the requested operation should be
// performed under the context of ECDSA instead of the default Ed25519.
func ECDSA(o bool) Option {
	return func(opts *Options) {
		if o {
			opts.SignatureAlgorithm = x509.ECDSAWithSHA512
		}
	}
}

// NotAfter sets the validity bound describing when a certificate expires.
func NotAfter(o time.Time) Option {
	return func(opts *Options) {
		opts.NotAfter = o
	}
}

// NotBefore sets the validity bound describing when a certificate becomes valid.
func NotBefore(o time.Time) Option {
	return func(opts *Options) {
		opts.NotBefore = o
	}
}

// NewDefaultOptions initializes the Options struct with default values.
func NewDefaultOptions(setters ...Option) *Options {
	opts := &Options{
		SignatureAlgorithm: x509.PureEd25519,
		IPAddresses:        []net.IP{},
		DNSNames:           []string{},
		Bits:               4096,
		NotAfter:           time.Now().Add(DefaultCertificateValidityDuration),
		NotBefore:          time.Now(),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	for _, setter := range setters {
		setter(opts)
	}

	return opts
}

// NewSerialNumber generates a random serial number for an X.509 certificate.
func NewSerialNumber() (*big.Int, error) {
	snLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	sn, err := rand.Int(rand.Reader, snLimit)
	if err != nil {
		return nil, err
	}

	return sn, nil
}

// NewSelfSignedCertificateAuthority creates a self-signed CA configured for
// server and client authentication.
func NewSelfSignedCertificateAuthority(setters ...Option) (*CertificateAuthority, error) {
	opts := NewDefaultOptions(setters...)

	serialNumber, err := NewSerialNumber()
	if err != nil {
		return nil, err
	}

	crt := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: opts.Organizations,
		},
		SignatureAlgorithm:    opts.SignatureAlgorithm,
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		IPAddresses: opts.IPAddresses,
		DNSNames:    opts.DNSNames,
	}

	switch opts.SignatureAlgorithm { //nolint:exhaustive
	case x509.SHA512WithRSA:
		return RSACertificateAuthority(crt, opts)
	case x509.PureEd25519:
		return Ed25519CertificateAuthority(crt)
	case x509.ECDSAWithSHA512:
		return ECDSACertificateAuthority(crt)
	default:
		return nil, fmt.Errorf("unsupported signature algorithm")
	}
}

// NewCertificateAuthorityFromCertificateAndKey builds CertificateAuthority from PEMEncodedCertificateAndKey.
func NewCertificateAuthorityFromCertificateAndKey(p *PEMEncodedCertificateAndKey) (*CertificateAuthority, error) {
	ca := &CertificateAuthority{
		CrtPEM: p.Crt,
		KeyPEM: p.Key,
	}

	var err error
	if ca.Crt, err = p.GetCert(); err != nil {
		return nil, err
	}

	ca.Key, err = p.GetKey()
	if err != nil {
		return nil, err
	}

	return ca, nil
}

// NewCertificateSigningRequest creates a CSR. If the IPAddresses or DNSNames options are not
// specified, the CSR will be generated with the default values set in
// NewDefaultOptions.
func NewCertificateSigningRequest(key interface{}, setters ...Option) (*CertificateSigningRequest, error) {
	opts := NewDefaultOptions(setters...)

	template := &x509.CertificateRequest{
		IPAddresses: opts.IPAddresses,
		DNSNames:    opts.DNSNames,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: opts.Organizations,
		},
	}

	switch key.(type) {
	case *rsa.PrivateKey:
		template.SignatureAlgorithm = x509.SHA512WithRSA
	case *ecdsa.PrivateKey:
		template.SignatureAlgorithm = x509.ECDSAWithSHA512
	case ed25519.PrivateKey:
		template.SignatureAlgorithm = x509.PureEd25519
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeCertificateRequest,
		Bytes: csrBytes,
	})

	csr := &CertificateSigningRequest{
		X509CertificateRequest:    template,
		X509CertificateRequestPEM: csrPEM,
	}

	return csr, nil
}

// NewECDSAKey generates an ECDSA key pair.
func NewECDSAKey() (*ECDSAKey, error) {
	keyEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(keyEC)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(keyEC.Public())
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeECPrivate,
		Bytes: keyBytes,
	})

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeECPublic,
		Bytes: publicKeyBytes,
	})

	key := &ECDSAKey{
		keyEC:        keyEC,
		KeyPEM:       keyPEM,
		PublicKeyPEM: publicKeyPEM,
	}

	return key, nil
}

// GetPrivateKeyPEM implements Key interface.
func (k *ECDSAKey) GetPrivateKeyPEM() []byte {
	return k.KeyPEM
}

// GetPublicKeyPEM implements Key interface.
func (k *ECDSAKey) GetPublicKeyPEM() []byte {
	return k.PublicKeyPEM
}

// NewEd25519Key generates an Ed25519 key pair.
func NewEd25519Key() (*Ed25519Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeEd25519Public,
		Bytes: pubBytes,
	})

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeEd25519Private,
		Bytes: privBytes,
	})

	key := &Ed25519Key{
		PublicKey:     pub,
		PrivateKey:    priv,
		PublicKeyPEM:  pubPEM,
		PrivateKeyPEM: privPEM,
	}

	return key, nil
}

// GetPrivateKeyPEM implements Key interface.
func (k *Ed25519Key) GetPrivateKeyPEM() []byte {
	return k.PrivateKeyPEM
}

// GetPublicKeyPEM implements Key interface.
func (k *Ed25519Key) GetPublicKeyPEM() []byte {
	return k.PublicKeyPEM
}

// NewRSAKey generates an RSA key pair.
func NewRSAKey() (*RSAKey, error) {
	keyRSA, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(keyRSA)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeRSAPrivate,
		Bytes: keyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&keyRSA.PublicKey)
	if err != nil {
		return nil, err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeRSAPublic,
		Bytes: publicKeyBytes,
	})

	key := &RSAKey{
		keyRSA:       keyRSA,
		KeyPEM:       keyPEM,
		PublicKeyPEM: publicKeyPEM,
	}

	return key, nil
}

// GetPrivateKeyPEM implements Key interface.
func (k *RSAKey) GetPrivateKeyPEM() []byte {
	return k.KeyPEM
}

// GetPublicKeyPEM implements Key interface.
func (k *RSAKey) GetPublicKeyPEM() []byte {
	return k.PublicKeyPEM
}

// NewCertificateFromCSR creates and signs X.509 certificate using the provided CSR.
func NewCertificateFromCSR(ca *x509.Certificate, key interface{}, csr *x509.CertificateRequest, setters ...Option) (*Certificate, error) {
	opts := NewDefaultOptions(setters...)

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("failed verifying CSR signature: %w", err)
	}

	serialNumber, err := NewSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber:          serialNumber,
		Issuer:                ca.Subject,
		Subject:               csr.Subject,
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotAfter,
		KeyUsage:              opts.KeyUsage,
		ExtKeyUsage:           opts.ExtKeyUsage,
		BasicConstraintsValid: false,
		IsCA:                  false,
		IPAddresses:           csr.IPAddresses,
		DNSNames:              csr.DNSNames,
	}

	crtDER, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, key)
	if err != nil {
		return nil, err
	}

	x509Certificate, err := x509.ParseCertificate(crtDER)
	if err != nil {
		return nil, err
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeCertificate,
		Bytes: crtDER,
	})

	crt := &Certificate{
		X509Certificate:    x509Certificate,
		X509CertificatePEM: crtPEM,
	}

	return crt, nil
}

// NewCertificateFromCSRBytes creates a signed certificate using the provided
// certificate, key, and CSR.
func NewCertificateFromCSRBytes(ca, key, csr []byte, setters ...Option) (*Certificate, error) {
	caPemBlock, _ := pem.Decode(ca)
	if caPemBlock == nil {
		return nil, fmt.Errorf("failed to decode CA")
	}

	caCrt, err := x509.ParseCertificate(caPemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyPemBlock, _ := pem.Decode(key)
	if keyPemBlock == nil {
		return nil, fmt.Errorf("failed to decode key")
	}

	var caKey interface{}

	switch keyPemBlock.Type {
	case PEMTypeRSAPrivate:
		caKey, err = x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes)
	case PEMTypeEd25519Private:
		caKey, err = x509.ParsePKCS8PrivateKey(keyPemBlock.Bytes)
	case PEMTypeECPrivate:
		caKey, err = x509.ParseECPrivateKey(keyPemBlock.Bytes)
	default:
		err = fmt.Errorf("unsupported PEM block: %v", keyPemBlock.Type)
	}

	if err != nil {
		return nil, err
	}

	csrPemBlock, _ := pem.Decode(csr)
	if csrPemBlock == nil {
		return nil, fmt.Errorf("failed to decode CSR")
	}

	request, err := x509.ParseCertificateRequest(csrPemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return NewCertificateFromCSR(caCrt, caKey, request, setters...)
}

// NewKeyPair generates a certificate signed by the provided CA, and a private
// key. The certifcate and private key are then used to create a
// tls.X509KeyPair.
func NewKeyPair(ca *CertificateAuthority, setters ...Option) (*KeyPair, error) {
	var (
		csr      *CertificateSigningRequest
		identity *PEMEncodedCertificateAndKey
		err      error
	)

	switch ca.Crt.SignatureAlgorithm { //nolint:exhaustive
	case x509.SHA512WithRSA:
		csr, identity, err = NewRSACSRAndIdentity(setters...)
		if err != nil {
			return nil, fmt.Errorf("failed to create RSA CSR and identity: %w", err)
		}
	case x509.ECDSAWithSHA512:
		csr, identity, err = NewECDSACSRAndIdentity(setters...)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECDSA CSR and identity: %w", err)
		}
	case x509.PureEd25519:
		csr, identity, err = NewEd25519CSRAndIdentity(setters...)
		if err != nil {
			return nil, fmt.Errorf("failed to create Ed25519 CSR and identity: %w", err)
		}
	}

	crt, err := NewCertificateFromCSRBytes(ca.CrtPEM, ca.KeyPEM, csr.X509CertificateRequestPEM, setters...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new certificate: %w", err)
	}

	x509KeyPair, err := tls.X509KeyPair(crt.X509CertificatePEM, identity.Key)
	if err != nil {
		return nil, err
	}

	keypair := &KeyPair{
		Certificate: &x509KeyPair,
		CrtPEM:      crt.X509CertificatePEM,
		KeyPEM:      identity.Key,
	}

	return keypair, nil
}

// NewCertificateAndKeyFromFiles initializes and returns a
// PEMEncodedCertificateAndKey from the path to a crt and key.
func NewCertificateAndKeyFromFiles(crt, key string) (*PEMEncodedCertificateAndKey, error) {
	p := &PEMEncodedCertificateAndKey{}

	crtBytes, err := ioutil.ReadFile(crt)
	if err != nil {
		return nil, err
	}

	p.Crt = crtBytes

	keyBytes, err := ioutil.ReadFile(key)
	if err != nil {
		return nil, err
	}

	p.Key = keyBytes

	return p, nil
}

// NewCertificateAndKeyFromCertificateAuthority initializes and returns a
// PEMEncodedCertificateAndKey from the CertificateAuthority.
func NewCertificateAndKeyFromCertificateAuthority(ca *CertificateAuthority) *PEMEncodedCertificateAndKey {
	return &PEMEncodedCertificateAndKey{
		Crt: ca.CrtPEM,
		Key: ca.KeyPEM,
	}
}

// NewCertificateAndKeyFromKeyPair initializes and returns a
// PEMEncodedCertificateAndKey from the KeyPair.
func NewCertificateAndKeyFromKeyPair(keyPair *KeyPair) *PEMEncodedCertificateAndKey {
	return &PEMEncodedCertificateAndKey{
		Crt: keyPair.CrtPEM,
		Key: keyPair.KeyPEM,
	}
}

// NewEd25519CSRAndIdentity generates and PEM encoded certificate and key, along with a
// CSR for the generated key.
func NewEd25519CSRAndIdentity(setters ...Option) (*CertificateSigningRequest, *PEMEncodedCertificateAndKey, error) {
	key, err := NewEd25519Key()
	if err != nil {
		return nil, nil, err
	}

	identity := &PEMEncodedCertificateAndKey{
		Key: key.PrivateKeyPEM,
	}

	csr, err := NewCertificateSigningRequest(key.PrivateKey, setters...)
	if err != nil {
		return nil, nil, err
	}

	return csr, identity, nil
}

// NewRSACSRAndIdentity generates and PEM encoded certificate and key, along with a
// CSR for the generated key.
func NewRSACSRAndIdentity(setters ...Option) (*CertificateSigningRequest, *PEMEncodedCertificateAndKey, error) {
	key, err := NewRSAKey()
	if err != nil {
		return nil, nil, err
	}

	identity := &PEMEncodedCertificateAndKey{
		Key: key.KeyPEM,
	}

	csr, err := NewCertificateSigningRequest(key.keyRSA, setters...)
	if err != nil {
		return nil, nil, err
	}

	return csr, identity, nil
}

// NewECDSACSRAndIdentity generates and PEM encoded certificate and key, along with a
// CSR for the generated key.
func NewECDSACSRAndIdentity(setters ...Option) (*CertificateSigningRequest, *PEMEncodedCertificateAndKey, error) {
	key, err := NewECDSAKey()
	if err != nil {
		return nil, nil, err
	}

	identity := &PEMEncodedCertificateAndKey{
		Key: key.KeyPEM,
	}

	csr, err := NewCertificateSigningRequest(key.keyEC, setters...)
	if err != nil {
		return nil, nil, err
	}

	return csr, identity, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for
// PEMEncodedCertificateAndKey. It is expected that the Crt and Key are a base64
// encoded string in the YAML file. This function decodes the strings into byte
// slices.
func (p *PEMEncodedCertificateAndKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var aux struct {
		Crt string `yaml:"crt"`
		Key string `yaml:"key"`
	}

	if err := unmarshal(&aux); err != nil {
		return err
	}

	decodedCrt, err := base64.StdEncoding.DecodeString(aux.Crt)
	if err != nil {
		return err
	}

	decodedKey, err := base64.StdEncoding.DecodeString(aux.Key)
	if err != nil {
		return err
	}

	p.Crt = decodedCrt
	p.Key = decodedKey

	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for
// PEMEncodedCertificateAndKey. It is expected that the Crt and Key are a base64
// encoded string in the YAML file. This function encodes the byte slices into
// strings.
func (p *PEMEncodedCertificateAndKey) MarshalYAML() (interface{}, error) {
	var aux struct {
		Crt string `yaml:"crt"`
		Key string `yaml:"key"`
	}

	aux.Crt = base64.StdEncoding.EncodeToString(p.Crt)
	aux.Key = base64.StdEncoding.EncodeToString(p.Key)

	return aux, nil
}

// GetCert parses PEM-encoded certificate as x509.Certificate.
func (p *PEMEncodedCertificateAndKey) GetCert() (*x509.Certificate, error) {
	block, _ := pem.Decode(p.Crt)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// GetKey parses either RSA or Ed25519 PEM-encoded key.
func (p *PEMEncodedCertificateAndKey) GetKey() (interface{}, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	switch block.Type {
	case PEMTypeRSAPrivate:
		return p.GetRSAKey()
	case PEMTypeEd25519Private:
		return p.GetEd25519Key()
	case PEMTypeECPrivate:
		return p.GetECDSAKey()
	default:
		return nil, fmt.Errorf("unsupported key type: %q", block.Type)
	}
}

// GetRSAKey parses PEM-encoded RSA key.
func (p *PEMEncodedCertificateAndKey) GetRSAKey() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key: %w", err)
	}

	return key, nil
}

// GetEd25519Key parses PEM-encoded Ed25519 key.
func (p *PEMEncodedCertificateAndKey) GetEd25519Key() (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Ed25519 key: %w", err)
	}

	ed25519Key, ok := key.(ed25519.PrivateKey)

	if !ok {
		return nil, fmt.Errorf("failed parsing Ed25519 key, got wrong key type")
	}

	return ed25519Key, nil
}

// GetECDSAKey parses PEM-encoded ECDSA key.
func (p *PEMEncodedCertificateAndKey) GetECDSAKey() (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	ecdsaKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA key: %w", err)
	}

	return ecdsaKey, nil
}

// DeepCopy implements DeepCopy interface.
func (p *PEMEncodedCertificateAndKey) DeepCopy() *PEMEncodedCertificateAndKey {
	if p == nil {
		return nil
	}

	out := new(PEMEncodedCertificateAndKey)
	p.DeepCopyInto(out)

	return out
}

// DeepCopyInto implements DeepCopy interface.
func (p *PEMEncodedCertificateAndKey) DeepCopyInto(out *PEMEncodedCertificateAndKey) {
	out.Crt = append([]byte(nil), p.Crt...)
	out.Key = append([]byte(nil), p.Key...)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for
// PEMEncodedKey. It is expected that the Key is a base64
// encoded string in the YAML file. This function decodes the strings into byte
// slices.
func (p *PEMEncodedKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var aux struct {
		Key string `yaml:"key"`
	}

	if err := unmarshal(&aux); err != nil {
		return err
	}

	decodedKey, err := base64.StdEncoding.DecodeString(aux.Key)
	if err != nil {
		return err
	}

	p.Key = decodedKey

	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for
// PEMEncodedCertificateAndKey. It is expected that the Crt and Key are a base64
// encoded string in the YAML file. This function encodes the byte slices into
// strings.
func (p *PEMEncodedKey) MarshalYAML() (interface{}, error) {
	var aux struct {
		Key string `yaml:"key"`
	}

	aux.Key = base64.StdEncoding.EncodeToString(p.Key)

	return aux, nil
}

// GetKey parses one of RSAKey, ECDSAKey or Ed25519Key.
func (p *PEMEncodedKey) GetKey() (Key, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	switch block.Type {
	case PEMTypeRSAPrivate:
		return p.GetRSAKey()
	case PEMTypeECPrivate:
		return p.GetECDSAKey()
	case PEMTypeEd25519Private:
		return p.GetEd25519Key()
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
}

// GetRSAKey parses PEM-encoded RSA key.
func (p *PEMEncodedKey) GetRSAKey() (*RSAKey, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key: %w", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeRSAPublic,
		Bytes: publicKeyBytes,
	})

	return &RSAKey{
		keyRSA:       key,
		KeyPEM:       p.Key,
		PublicKeyPEM: publicKeyPEM,
	}, nil
}

// GetEd25519Key parses PEM-encoded Ed25519 key.
func (p *PEMEncodedKey) GetEd25519Key() (*Ed25519Key, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Ed25519 key: %w", err)
	}

	ed25519Key, ok := key.(ed25519.PrivateKey)

	if !ok {
		return nil, fmt.Errorf("failed parsing Ed25519 key, got wrong key type")
	}

	publicKey := ed25519Key.Public()

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed encoding public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeEd25519Public,
		Bytes: pubBytes,
	})

	return &Ed25519Key{
		PrivateKey:    ed25519Key,
		PublicKey:     publicKey.(ed25519.PublicKey),
		PrivateKeyPEM: p.Key,
		PublicKeyPEM:  pubPEM,
	}, nil
}

// GetECDSAKey parses PEM-encoded ECDSA key.
func (p *PEMEncodedKey) GetECDSAKey() (*ECDSAKey, error) {
	block, _ := pem.Decode(p.Key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	ecdsaKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA key: %w", err)
	}

	publicKey := ecdsaKey.Public()

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed encoding public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeECPublic,
		Bytes: pubBytes,
	})

	return &ECDSAKey{
		keyEC:        ecdsaKey,
		KeyPEM:       p.Key,
		PublicKeyPEM: pubPEM,
	}, nil
}

// DeepCopy implements DeepCopy interface.
func (p *PEMEncodedKey) DeepCopy() *PEMEncodedKey {
	if p == nil {
		return nil
	}

	out := new(PEMEncodedKey)
	p.DeepCopyInto(out)

	return out
}

// DeepCopyInto implements DeepCopy interface.
func (p *PEMEncodedKey) DeepCopyInto(out *PEMEncodedKey) {
	out.Key = append([]byte(nil), p.Key...)
}

// NewCertficateAndKey is the NewCertificateAndKey with a typo in the name.
//
// Deprecated: use NewCertificateAndKey instead.
func NewCertficateAndKey(crt *x509.Certificate, key interface{}, setters ...Option) (*PEMEncodedCertificateAndKey, error) {
	return NewCertificateAndKey(crt, key, setters...)
}

// NewCertificateAndKey generates a new key and certificate signed by a CA.
func NewCertificateAndKey(crt *x509.Certificate, key interface{}, setters ...Option) (*PEMEncodedCertificateAndKey, error) {
	var (
		k, priv  interface{}
		pemBytes []byte
		err      error
	)

	switch key.(type) {
	case *rsa.PrivateKey:
		k, err = NewRSAKey()
		if err != nil {
			return nil, fmt.Errorf("failed to create new RSA key: %w", err)
		}

		priv = k.(*RSAKey).keyRSA
		pemBytes = k.(*RSAKey).KeyPEM
	case *ecdsa.PrivateKey:
		k, err = NewECDSAKey()
		if err != nil {
			return nil, fmt.Errorf("failed to create new RSA key: %w", err)
		}

		priv = k.(*ECDSAKey).keyEC
		pemBytes = k.(*ECDSAKey).KeyPEM
	case ed25519.PrivateKey:
		k, err = NewEd25519Key()
		if err != nil {
			return nil, fmt.Errorf("failed to create new Ed25519 key: %w", err)
		}

		priv = k.(*Ed25519Key).PrivateKey
		pemBytes = k.(*Ed25519Key).PrivateKeyPEM
	}

	csr, err := NewCertificateSigningRequest(priv, setters...)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	block, _ := pem.Decode(csr.X509CertificateRequestPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM encoded CSR")
	}

	cr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	c, err := NewCertificateFromCSR(crt, key, cr, setters...)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate from CSR: %w", err)
	}

	p := &PEMEncodedCertificateAndKey{
		Crt: c.X509CertificatePEM,
		Key: pemBytes,
	}

	return p, nil
}

// Hash calculates the SHA-256 hash of the Subject Public Key Information (SPKI)
// object in an x509 certificate (in DER encoding). It returns the full hash as
// a hex encoded string (suitable for passing to Set.Allow). See
// https://github.com/kubernetes/kubernetes/blob/f557e0f7e3ee9089769ed3f03187fdd4acbb9ac1/cmd/kubeadm/app/util/pubkeypin/pubkeypin.go
func Hash(crt *x509.Certificate) string {
	spkiHash := sha256.Sum256(crt.RawSubjectPublicKeyInfo)

	return "sha256" + ":" + strings.ToLower(hex.EncodeToString(spkiHash[:]))
}

// RSACertificateAuthority creates an RSA CA.
func RSACertificateAuthority(template *x509.Certificate, opts *Options) (*CertificateAuthority, error) {
	key, err := rsa.GenerateKey(rand.Reader, opts.Bits)
	if err != nil {
		return nil, err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeRSAPrivate,
		Bytes: keyBytes,
	})

	crtDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(crtDER)
	if err != nil {
		return nil, err
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeCertificate,
		Bytes: crtDER,
	})

	ca := &CertificateAuthority{
		Crt:    crt,
		CrtPEM: crtPEM,
		Key:    key,
		KeyPEM: keyPEM,
	}

	return ca, nil
}

// ECDSACertificateAuthority creates an ECDSA CA.
func ECDSACertificateAuthority(template *x509.Certificate) (*CertificateAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeECPrivate,
		Bytes: keyBytes,
	})

	crtDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(crtDER)
	if err != nil {
		return nil, err
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeCertificate,
		Bytes: crtDER,
	})

	ca := &CertificateAuthority{
		Crt:    crt,
		CrtPEM: crtPEM,
		Key:    key,
		KeyPEM: keyPEM,
	}

	return ca, nil
}

// Ed25519CertificateAuthority creates an Ed25519 CA.
func Ed25519CertificateAuthority(template *x509.Certificate) (*CertificateAuthority, error) {
	key, err := NewEd25519Key()
	if err != nil {
		return nil, fmt.Errorf("failed to create new Ed25519 key: %w", err)
	}

	crtDER, err := x509.CreateCertificate(rand.Reader, template, template, key.PublicKey, key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Ed25519 CA certificate: %w", err)
	}

	crt, err := x509.ParseCertificate(crtDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Ed25519 CA certificate: %w", err)
	}

	crtPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PEMTypeCertificate,
		Bytes: crtDER,
	})

	ca := &CertificateAuthority{
		Crt:    crt,
		CrtPEM: crtPEM,
		Key:    key,
		KeyPEM: key.PrivateKeyPEM,
	}

	return ca, nil
}
