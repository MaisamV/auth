package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	// Create keys directory if it doesn't exist
	keysDir := "keys"
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		log.Fatalf("Failed to create keys directory: %v", err)
	}

	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Marshal private key to PKCS8 format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to marshal private key: %v", err)
	}

	// Create PEM block for private key
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Marshal public key to PKIX format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	// Create PEM block for public key
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Write private key to file
	privateKeyPath := filepath.Join(keysDir, "jwt-private.pem")
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		log.Fatalf("Failed to write private key: %v", err)
	}

	// Write public key to file
	publicKeyPath := filepath.Join(keysDir, "jwt-public.pem")
	if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
		log.Fatalf("Failed to write public key: %v", err)
	}

	fmt.Printf("✅ JWT key pair generated successfully!\n")
	fmt.Printf("📁 Private key: %s\n", privateKeyPath)
	fmt.Printf("📁 Public key: %s\n", publicKeyPath)
	fmt.Printf("🔒 Private key permissions: 0600 (owner read/write only)\n")
	fmt.Printf("🔓 Public key permissions: 0644 (owner read/write, others read)\n")
	fmt.Printf("\n⚠️  Important: Keep the private key secure and never commit it to version control!\n")
}