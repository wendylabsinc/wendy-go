package devicecerts

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// LeafCertificatePEM returns only the first CERTIFICATE block from a PEM bundle.
// Some pki-core certificates include trailing bytes after the outer ASN.1
// certificate SEQUENCE; re-encoding only that first ASN.1 element keeps the
// certificate acceptable to Go TLS clients.
func LeafCertificatePEM(certPEM string) (string, error) {
	rest := []byte(certPEM)
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		var raw asn1.RawValue
		if trailing, err := asn1.Unmarshal(block.Bytes, &raw); err == nil && len(trailing) > 0 {
			block = &pem.Block{
				Type:    block.Type,
				Headers: block.Headers,
				Bytes:   raw.FullBytes,
			}
		}
		return string(pem.EncodeToMemory(block)), nil
	}
	return "", fmt.Errorf("no CERTIFICATE block found")
}
