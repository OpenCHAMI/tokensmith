package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// KeyManager handles RSA key pair management
type KeyManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	privateJwk jwk.Key
	publicJwk  jwk.Key
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

	// Convert to JWK
	privateJwk, err := jwk.FromRaw(privateKey)
	if err != nil {
		return fmt.Errorf("failed to create private JWK: %w", err)
	}

	publicJwk, err := jwk.PublicKeyOf(privateJwk)
	if err != nil {
		return fmt.Errorf("failed to create public JWK: %w", err)
	}

	// Set key metadata
	if err := privateJwk.Set(jwk.KeyTypeKey, jwa.RSA); err != nil {
		return fmt.Errorf("failed to set private key type: %w", err)
	}
	if err := privateJwk.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return fmt.Errorf("failed to set private key algorithm: %w", err)
	}

	if err := publicJwk.Set(jwk.KeyTypeKey, jwa.RSA); err != nil {
		return fmt.Errorf("failed to set public key type: %w", err)
	}
	if err := publicJwk.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return fmt.Errorf("failed to set public key algorithm: %w", err)
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey
	km.privateJwk = privateJwk
	km.publicJwk = publicJwk
	return nil
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

	// Convert to JWK
	publicJwk, err := jwk.FromRaw(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create public JWK: %w", err)
	}

	// Set key metadata
	if err := publicJwk.Set(jwk.KeyTypeKey, jwa.RSA); err != nil {
		return fmt.Errorf("failed to set public key type: %w", err)
	}
	if err := publicJwk.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return fmt.Errorf("failed to set public key algorithm: %w", err)
	}

	km.publicKey = publicKey
	km.publicJwk = publicJwk
	return nil
}

// GenerateKeyPair generates a new RSA key pair
func (km *KeyManager) GenerateKeyPair(bits int) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Convert to JWK
	privateJwk, err := jwk.FromRaw(privateKey)
	if err != nil {
		return fmt.Errorf("failed to create private JWK: %w", err)
	}

	publicJwk, err := jwk.PublicKeyOf(privateJwk)
	if err != nil {
		return fmt.Errorf("failed to create public JWK: %w", err)
	}

	// Set key metadata
	if err := privateJwk.Set(jwk.KeyTypeKey, jwa.RSA); err != nil {
		return fmt.Errorf("failed to set private key type: %w", err)
	}
	if err := privateJwk.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return fmt.Errorf("failed to set private key algorithm: %w", err)
	}

	if err := publicJwk.Set(jwk.KeyTypeKey, jwa.RSA); err != nil {
		return fmt.Errorf("failed to set public key type: %w", err)
	}
	if err := publicJwk.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return fmt.Errorf("failed to set public key algorithm: %w", err)
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey
	km.privateJwk = privateJwk
	km.publicJwk = publicJwk
	return nil
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

	// Encode private key to PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(km.privateKey),
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

	// Encode public key to PEM
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(km.publicKey),
	})

	// Write to file
	if err := os.WriteFile(keyPath, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}

	return nil
}

// GetPrivateKey returns the private key
func (km *KeyManager) GetPrivateKey() (*rsa.PrivateKey, error) {
	if km.privateKey == nil {
		return nil, fmt.Errorf("no private key available")
	}
	return km.privateKey, nil
}

// GetPublicKey returns the public key
func (km *KeyManager) GetPublicKey() (*rsa.PublicKey, error) {
	if km.publicKey == nil {
		return nil, fmt.Errorf("no public key available")
	}
	return km.publicKey, nil
}

// GetPrivateJWK returns the private key as a JWK
func (km *KeyManager) GetPrivateJWK() (jwk.Key, error) {
	if km.privateJwk == nil {
		return nil, fmt.Errorf("no private key available")
	}
	return km.privateJwk, nil
}

// GetPublicJWK returns the public key as a JWK
func (km *KeyManager) GetPublicJWK() (jwk.Key, error) {
	if km.publicJwk == nil {
		return nil, fmt.Errorf("no public key available")
	}
	return km.publicJwk, nil
}

// SetKeyPair sets the RSA key pair for the KeyManager
func (km *KeyManager) SetKeyPair(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) error {
	if privateKey == nil || publicKey == nil {
		return fmt.Errorf("both private and public keys must be provided")
	}

	// Convert private key to JWK
	privateJwk, err := jwk.FromRaw(privateKey)
	if err != nil {
		return fmt.Errorf("failed to convert private key to JWK: %w", err)
	}

	// Convert public key to JWK
	publicJwk, err := jwk.FromRaw(publicKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key to JWK: %w", err)
	}

	// Set key type and algorithm
	if err := privateJwk.Set(jwk.KeyTypeKey, jwa.RSA); err != nil {
		return fmt.Errorf("failed to set private key type: %w", err)
	}
	if err := privateJwk.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return fmt.Errorf("failed to set private key algorithm: %w", err)
	}

	if err := publicJwk.Set(jwk.KeyTypeKey, jwa.RSA); err != nil {
		return fmt.Errorf("failed to set public key type: %w", err)
	}
	if err := publicJwk.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return fmt.Errorf("failed to set public key algorithm: %w", err)
	}

	km.privateKey = privateKey
	km.publicKey = publicKey
	km.privateJwk = privateJwk
	km.publicJwk = publicJwk

	return nil
}
