// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package x509

import "time"

// DefaultCertificateValidityDuration is a default certificate lifetime.
const DefaultCertificateValidityDuration = 24 * time.Hour

// PEM Block Header Types.
const (
	PEMTypeRSAPrivate     = "RSA PRIVATE KEY"
	PEMTypeRSAPublic      = "PUBLIC KEY"
	PEMTypeECPrivate      = "EC PRIVATE KEY"
	PEMTypeECPublic       = "EC PUBLIC KEY"
	PEMTypeEd25519Private = "ED25519 PRIVATE KEY"
	PEMTypeEd25519Public  = "ED25519 PUBLIC KEY"

	PEMTypeCertificate        = "CERTIFICATE"
	PEMTypeCertificateRequest = "CERTIFICATE REQUEST"
)
