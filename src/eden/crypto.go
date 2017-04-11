/*-
 * Copyright (C) 2017, Vi Grey
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

package main

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "crypto/tls"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/pem"
  "math/big"
  "os"
  "strconv"
  "time"
)

// Get a random int between 0 and number
func getRandNumber(number int64) int {
  randNumber, _ := rand.Int(rand.Reader, big.NewInt(number))
  randString := randNumber.String()
  randInt, _ := strconv.Atoi(randString)
  return randInt
}

// Generate a random byte array of size length
func randByteArray(size int) []byte {
  randValue := make([]byte, size)
  if _, err := rand.Read(randValue); err != nil {
    panic(err)
  }
  return randValue
}

func pemBlockForKey(priv *ecdsa.PrivateKey) *pem.Block {
  b, err := x509.MarshalECPrivateKey(priv)
  if err != nil {
    panic(err)
  }
  return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
}

func generateTLSCert() tls.Certificate {
  _, err1 := os.Stat(configDir + "/auth/cert.pem")
  _, err2 := os.Stat(configDir + "/auth/key.pem")
  if os.IsNotExist(err1) && os.IsNotExist(err2) {
    privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
      panic(err)
    }
    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
    if err != nil {
      panic("Error creating TLS Serial Number")
    }
    certificateTemplate := x509.Certificate{
      SerialNumber: serialNumber,
      Subject: pkix.Name{
        Organization: []string{"Eden"},
      },
      NotBefore: time.Now().Add(-720 * time.Hour).UTC(),
      NotAfter: time.Now().Add(876000 * time.Hour).UTC(),
      KeyUsage: (x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature),
      ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
      BasicConstraintsValid: true,
      DNSNames: []string{serverAddress},
    }
    serialNumber = nil
    derBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate,
                                            &certificateTemplate,
                                            &privkey.PublicKey, privkey)
    if err != nil {
      panic("Error creating X509 Certificate")
    }
    cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
    key := pem.EncodeToMemory(pemBlockForKey(privkey))
    writeAuthKey(cert, key)
    cer, err := tls.X509KeyPair(cert, key)
    if err != nil {
      panic("Error creating TLS Certificate")
    }
    return cer
  } else {
    cer, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
    if err != nil {
      panic(err)
    }
    return cer
  }
}
