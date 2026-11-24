package gate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"time"
)

// CA is a per-run local certificate authority used to terminate TLS for
// hosts whose traffic must be inspected (secret injection, record mode).
// Its private key exists only in this process's memory and is discarded at
// the end of the run; only the certificate is placed in the shell's trust
// store.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	leafKey *ecdsa.PrivateKey
	pem     []byte
	mu      sync.Mutex
	cache   map[string]*tls.Certificate
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// NewCA creates a CA. When permitted is non-empty the CA carries X.509 name
// constraints so it can only ever vouch for those hosts.
func NewCA(runID string, permitted []string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "SecureAIWarp per-run CA " + runID, Organization: []string{"SecureAIWarp"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	if len(permitted) > 0 {
		tmpl.PermittedDNSDomainsCritical = true
		for _, h := range permitted {
			if ip, err := netip.ParseAddr(h); err == nil {
				bits := 32
				if ip.Is6() {
					bits = 128
				}
				tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(bits, bits)})
			} else {
				tmpl.PermittedDNSDomains = append(tmpl.PermittedDNSDomains, h)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert: cert, key: key, leafKey: leafKey,
		pem:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cache: map[string]*tls.Certificate{},
	}, nil
}

// CertPEM returns the CA certificate in PEM form (for the shell trust store).
func (c *CA) CertPEM() []byte { return c.pem }

// Leaf returns a server certificate for host.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.cache[host]; ok {
		return l, nil
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		tmpl.IPAddresses = []net.IP{ip.AsSlice()}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &c.leafKey.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	l := &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: c.leafKey}
	c.cache[host] = l
	return l, nil
}
