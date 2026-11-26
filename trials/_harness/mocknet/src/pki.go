package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Domains the mock CA may ever vouch for (X.509 name constraints, critical).
// Even though the CA is installed in the system trust store, it cannot be
// used to impersonate any other site.
var caPermitted = []string{"open-meteo.com", "exchangerate-api.com", "api.anthropic.com", "example.com", "example.org", "example.net"}

func randSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

// cmdPKI creates ca.pem/ca.key (if missing) and (re)issues leaf.pem/leaf.key
// for the given hosts.
func cmdPKI(args []string) error {
	fs := flag.NewFlagSet("pki", flag.ExitOnError)
	dir := fs.String("dir", "pki", "output directory")
	hosts := fs.String("hosts", "", "comma separated DNS names for the leaf")
	fs.Parse(args)
	os.MkdirAll(*dir, 0o755)
	caPath, caKeyPath := filepath.Join(*dir, "ca.pem"), filepath.Join(*dir, "ca.key")
	var ca *x509.Certificate
	var caKey *ecdsa.PrivateKey
	if b, err := os.ReadFile(caPath); err == nil {
		kb, err := os.ReadFile(caKeyPath)
		if err != nil {
			return err
		}
		blk, _ := pem.Decode(b)
		if ca, err = x509.ParseCertificate(blk.Bytes); err != nil {
			return err
		}
		kblk, _ := pem.Decode(kb)
		if caKey, err = x509.ParseECPrivateKey(kblk.Bytes); err != nil {
			return err
		}
		fmt.Println("pki: reusing existing CA", caPath)
	} else {
		caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		t := &x509.Certificate{
			SerialNumber:                randSerial(),
			Subject:                     pkix.Name{CommonName: "mocknet trial CA (local, fake upstream)", Organization: []string{"mocknet trial"}},
			NotBefore:                   time.Now().Add(-24 * time.Hour),
			NotAfter:                    time.Now().AddDate(2, 0, 0),
			IsCA:                        true,
			BasicConstraintsValid:       true,
			MaxPathLen:                  0,
			MaxPathLenZero:              true,
			KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			PermittedDNSDomainsCritical: true,
			PermittedDNSDomains:         caPermitted,
		}
		der, err := x509.CreateCertificate(rand.Reader, t, t, &caKey.PublicKey, caKey)
		if err != nil {
			return err
		}
		ca, _ = x509.ParseCertificate(der)
		kb, _ := x509.MarshalECPrivateKey(caKey)
		if err := writePEM(caKeyPath, "EC PRIVATE KEY", kb, 0o600); err != nil {
			return err
		}
		if err := writePEM(caPath, "CERTIFICATE", der, 0o644); err != nil {
			return err
		}
		fmt.Println("pki: created CA", caPath)
	}
	var names []string
	for _, h := range strings.Split(*hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			names = append(names, h)
		}
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, lt, ca, &k.PublicKey, caKey)
	if err != nil {
		return err
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	if err := writePEM(filepath.Join(*dir, "leaf.key"), "EC PRIVATE KEY", kb, 0o600); err != nil {
		return err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(*dir, "leaf.pem"), chain, 0o644); err != nil {
		return err
	}
	fmt.Printf("pki: issued leaf for %d names\n", len(names))
	return nil
}
