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
	// Read the PEM file
	pemData, err := ioutil.ReadFile("keys/jwt-public.pem")
	if err != nil {
		log.Fatal("Error reading PEM file:", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Fatal("Failed to decode PEM block")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal("Error parsing public key:", err)
	}

	// Cast to ECDSA public key
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Not an ECDSA public key")
	}

	// Extract x and y coordinates
	x := ecdsaPubKey.X
	y := ecdsaPubKey.Y

	fmt.Printf("Public Key Coordinates:\n")
	fmt.Printf("X (hex): %x\n", x)
	fmt.Printf("Y (hex): %x\n", y)

	// Convert to 32-byte arrays (for P-256)
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	x.FillBytes(xBytes)
	y.FillBytes(yBytes)

	// Base64URL encode
	xBase64 := base64.RawURLEncoding.EncodeToString(xBytes)
	yBase64 := base64.RawURLEncoding.EncodeToString(yBytes)

	fmt.Printf("\nJWKS Format:\n")
	fmt.Printf("X (base64url): %s\n", xBase64)
	fmt.Printf("Y (base64url): %s\n", yBase64)

	// Compare with current JWKS response
	fmt.Printf("\nCurrent JWKS response has:\n")
	fmt.Printf("X: 58l_lQC51SZfnsK5jldCFYGSXfzvvGLGbCPu9zCrgo0\n")
	fmt.Printf("Y: v-G_Ha54GUPR80yy-99BpRn6i8ow_E52Fpv3DaFrwcI\n")

	fmt.Printf("\nDo they match?\n")
	fmt.Printf("X matches: %t\n", xBase64 == "58l_lQC51SZfnsK5jldCFYGSXfzvvGLGbCPu9zCrgo0")
	fmt.Printf("Y matches: %t\n", yBase64 == "v-G_Ha54GUPR80yy-99BpRn6i8ow_E52Fpv3DaFrwcI")
}