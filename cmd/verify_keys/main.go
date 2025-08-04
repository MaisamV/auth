package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	// Read the private key file
	privateKeyData, err := ioutil.ReadFile("keys/jwt-private.pem")
	if err != nil {
		log.Fatal("Error reading private key file:", err)
	}

	// Decode private key PEM block
	privateBlock, _ := pem.Decode(privateKeyData)
	if privateBlock == nil {
		log.Fatal("Failed to decode private key PEM block")
	}

	// Parse the private key
	privateKey, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		log.Fatal("Error parsing private key:", err)
	}

	// Cast to ECDSA private key
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatal("Not an ECDSA private key")
	}

	// Extract public key from private key
	publicKeyFromPrivate := &ecdsaPrivateKey.PublicKey

	// Read the standalone public key file
	publicKeyData, err := ioutil.ReadFile("keys/jwt-public.pem")
	if err != nil {
		log.Fatal("Error reading public key file:", err)
	}

	// Decode public key PEM block
	publicBlock, _ := pem.Decode(publicKeyData)
	if publicBlock == nil {
		log.Fatal("Failed to decode public key PEM block")
	}

	// Parse the standalone public key
	standalonePublicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		log.Fatal("Error parsing standalone public key:", err)
	}

	// Cast to ECDSA public key
	ecdsaStandalonePublicKey, ok := standalonePublicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Standalone key is not an ECDSA public key")
	}

	fmt.Println("=== Public Key from Private Key ===")
	fmt.Printf("X (hex): %x\n", publicKeyFromPrivate.X)
	fmt.Printf("Y (hex): %x\n", publicKeyFromPrivate.Y)

	// Convert to 32-byte arrays (for P-256)
	xBytesFromPrivate := make([]byte, 32)
	yBytesFromPrivate := make([]byte, 32)
	publicKeyFromPrivate.X.FillBytes(xBytesFromPrivate)
	publicKeyFromPrivate.Y.FillBytes(yBytesFromPrivate)

	// Base64URL encode
	xBase64FromPrivate := base64.RawURLEncoding.EncodeToString(xBytesFromPrivate)
	yBase64FromPrivate := base64.RawURLEncoding.EncodeToString(yBytesFromPrivate)

	fmt.Printf("X (base64url): %s\n", xBase64FromPrivate)
	fmt.Printf("Y (base64url): %s\n", yBase64FromPrivate)

	fmt.Println("\n=== Standalone Public Key ===")
	fmt.Printf("X (hex): %x\n", ecdsaStandalonePublicKey.X)
	fmt.Printf("Y (hex): %x\n", ecdsaStandalonePublicKey.Y)

	// Convert to 32-byte arrays (for P-256)
	xBytesStandalone := make([]byte, 32)
	yBytesStandalone := make([]byte, 32)
	ecdsaStandalonePublicKey.X.FillBytes(xBytesStandalone)
	ecdsaStandalonePublicKey.Y.FillBytes(yBytesStandalone)

	// Base64URL encode
	xBase64Standalone := base64.RawURLEncoding.EncodeToString(xBytesStandalone)
	yBase64Standalone := base64.RawURLEncoding.EncodeToString(yBytesStandalone)

	fmt.Printf("X (base64url): %s\n", xBase64Standalone)
	fmt.Printf("Y (base64url): %s\n", yBase64Standalone)

	fmt.Println("\n=== Comparison ===")
	fmt.Printf("Keys match: %t\n", publicKeyFromPrivate.X.Cmp(ecdsaStandalonePublicKey.X) == 0 && publicKeyFromPrivate.Y.Cmp(ecdsaStandalonePublicKey.Y) == 0)

	fmt.Println("\n=== Current JWKS Response ===")
	fmt.Println("X: EbeMheZfurkgfaIFhqHtGBM1ySKGM8tjseUirc62pTE")
	fmt.Println("Y: QdHjhfRskGCNlDOz4CQxryDfZVMoy1vyeLNZPpVErq0")

	fmt.Println("\n=== Which key does JWKS match? ===")
	fmt.Printf("Matches private key's public key: %t\n", xBase64FromPrivate == "EbeMheZfurkgfaIFhqHtGBM1ySKGM8tjseUirc62pTE" && yBase64FromPrivate == "QdHjhfRskGCNlDOz4CQxryDfZVMoy1vyeLNZPpVErq0")
	fmt.Printf("Matches standalone public key: %t\n", xBase64Standalone == "EbeMheZfurkgfaIFhqHtGBM1ySKGM8tjseUirc62pTE" && yBase64Standalone == "QdHjhfRskGCNlDOz4CQxryDfZVMoy1vyeLNZPpVErq0")
}