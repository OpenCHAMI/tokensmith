// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

// FIPS-compliant key sizes
const (
	// RSA key sizes (FIPS 186-4)
	MinRSAKeySize = 2048
)

// KeyManager manages cryptographic keys for JWT operations
type KeyManager struct {
	privateKey interface{}
	publicKey  interface{}
	kid        string
}

// NewKeyManager creates a new KeyManager instance
func NewKeyManager() *KeyManager {
	return &KeyManager{}
}

// LoadPrivateKey loads a private key from a PEM file
func (km *KeyManager) LoadPrivateKey(keyPath string) error {
	// Read the key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey
	return km.generateKIDFromPublicKey()
}

// LoadPublicKey loads a public key from a PEM file
func (km *KeyManager) LoadPublicKey(keyPath string) error {
	// Read the key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	// Parse the public key
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	km.publicKey = publicKey
	return km.generateKIDFromPublicKey()
}

// generate KID from public key
func (km *KeyManager) generateKIDFromPublicKey() error {
	kid, err := RFC7638Thumbprint(km.publicKey)
	if err != nil {
		return fmt.Errorf("generate RFC 7638 key id: %w", err)
	}
	km.kid = kid
	return nil
}

// RFC7638Thumbprint computes a JWK thumbprint-style key ID (SHA-256, base64url)
// for supported public key types according to RFC 7638 canonical members.
func RFC7638Thumbprint(publicKey interface{}) (string, error) {
	canonicalJWK, err := canonicalJWKForThumbprint(publicKey)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256([]byte(canonicalJWK))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// IsRFC7638Thumbprint returns true when kid is a base64url-encoded SHA-256
// JWK thumbprint as produced by RFC7638Thumbprint.
func IsRFC7638Thumbprint(kid string) bool {
	if kid == "" {
		return false
	}

	raw, err := base64.RawURLEncoding.DecodeString(kid)
	if err != nil {
		return false
	}

	return len(raw) == sha256.Size
}

func canonicalJWKForThumbprint(publicKey interface{}) (string, error) {
	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		return canonicalRSAJWK(k), nil
	case rsa.PublicKey:
		return canonicalRSAJWK(&k), nil
	case *ecdsa.PublicKey:
		return canonicalECJWK(k)
	case ecdsa.PublicKey:
		return canonicalECJWK(&k)
	default:
		return "", fmt.Errorf("unsupported key type %T", publicKey)
	}
}

func canonicalRSAJWK(k *rsa.PublicKey) string {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
	return fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
		e,
		n,
	)
}

func canonicalECJWK(k *ecdsa.PublicKey) (string, error) {
	curve, err := jwkCurveName(k.Curve)
	if err != nil {
		return "", err
	}
	x := base64.RawURLEncoding.EncodeToString(k.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(k.Y.Bytes())

	return fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
		curve,
		x,
		y,
	), nil
}

func jwkCurveName(c elliptic.Curve) (string, error) {
	switch c {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	default:
		return "", fmt.Errorf("unsupported EC curve %s", c.Params().Name)
	}
}

// GenerateKeyPair generates a new RSA key pair with FIPS-compliant key size
func (km *KeyManager) GenerateRSAKeyPair() error {
	// Generate RSA key pair with minimum 2048 bits (FIPS 186-4)
	privateKey, err := rsa.GenerateKey(rand.Reader, MinRSAKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey
	return km.generateKIDFromPublicKey()
}

// GenerateECKeyPair generates a new ECDSA key pair using a FIPS-compliant curve
func (km *KeyManager) GenerateECKeyPair() error {
	// Generate ECDSA key pair using P-256 curve (FIPS 186-4)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey
	return km.generateKIDFromPublicKey()
}

// SavePrivateKey saves the private key to a PEM file
func (km *KeyManager) SavePrivateKey(keyPath string) error {
	if km.privateKey == nil {
		return fmt.Errorf("no private key available")
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Get RSA private key
	privateKey, ok := km.privateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not an RSA key")
	}

	// Encode private key to PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Write to file
	if err := os.WriteFile(keyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}

	return nil
}

// SavePublicKey saves the public key to a PEM file
func (km *KeyManager) SavePublicKey(keyPath string) error {
	if km.publicKey == nil {
		return fmt.Errorf("no public key available")
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Get RSA public key
	publicKey, ok := km.publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not an RSA key")
	}

	// Encode public key to PEM
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	})

	// Write to file
	if err := os.WriteFile(keyPath, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}

	return nil
}

// GetPrivateKey returns the private key
func (km *KeyManager) GetPrivateKey() (interface{}, error) {
	if km.privateKey == nil {
		return nil, fmt.Errorf("private key not set")
	}
	return km.privateKey, nil
}

// GetPublicKey returns the public key
func (km *KeyManager) GetPublicKey() (interface{}, error) {
	if km.publicKey == nil {
		return nil, fmt.Errorf("public key not set")
	}
	return km.publicKey, nil
}

// GetKid returns kid value of public key
func (km *KeyManager) GetKid() (string, error) {
	if km.kid == "" {
		return "", fmt.Errorf("kid not set")
	}
	return km.kid, nil
}

// SetKeyPair sets the RSA key pair
func (km *KeyManager) SetKeyPair(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) error {
	// Validate key size
	if privateKey.N.BitLen() < MinRSAKeySize {
		return fmt.Errorf("RSA key size %d is below minimum required %d bits", privateKey.N.BitLen(), MinRSAKeySize)
	}

	km.privateKey = privateKey
	km.publicKey = publicKey
	return km.generateKIDFromPublicKey()
}

// SetECKeyPair sets the ECDSA key pair
func (km *KeyManager) SetECKeyPair(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) error {
	// Validate curve
	if privateKey.Curve.Params().BitSize < elliptic.P256().Params().BitSize {
		return fmt.Errorf("ECDSA curve %s is below minimum required P-256", privateKey.Curve.Params().Name)
	}

	km.privateKey = privateKey
	km.publicKey = publicKey
	return km.generateKIDFromPublicKey()
}

// GetRSAPrivateKey returns the RSA private key
func (km *KeyManager) GetRSAPrivateKey() (*rsa.PrivateKey, error) {
	if km.privateKey == nil {
		return nil, fmt.Errorf("private key not set")
	}

	privateKey, ok := km.privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}

	return privateKey, nil
}

// GetRSAPublicKey returns the RSA public key
func (km *KeyManager) GetRSAPublicKey() (*rsa.PublicKey, error) {
	if km.publicKey == nil {
		return nil, fmt.Errorf("public key not set")
	}

	publicKey, ok := km.publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an RSA key")
	}

	return publicKey, nil
}
