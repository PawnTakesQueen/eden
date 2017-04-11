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
  "crypto/tls"
  "crypto/x509"
  "io"
  "io/ioutil"
)

func handleResponse(response []byte) int {
  return len(response) // Temporary line until responses get figured out
}

func handleConn(conn *tls.Conn) {
  var response []byte
  defer conn.Close()
  for {
    // Read the incoming connection into the buffer.
    buf := make([]byte, 1024)
    resLen, err := conn.Read(buf)
    if err != nil && err != io.EOF {
      break
    } else {
      response = append(response, buf[:resLen]...)
      newIndex := handleResponse(response)
      response = response[newIndex:]
    }
    if err == io.EOF {
      break
    }
  }
}

func dialServer() {
  cert := generateTLSCert()
  clientCert, err := ioutil.ReadFile(tlsCert)
  if err != nil {
    panic(err)
  }
  clientCertPool := x509.NewCertPool()
  clientCertPool.AppendCertsFromPEM(clientCert)
  cfg := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ServerName: serverAddress,
    MinVersion: tls.VersionTLS12,
    CurvePreferences: []tls.CurveID{tls.X25519},
    PreferServerCipherSuites: true,
    CipherSuites: []uint16{
      tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    },
  }
  conn, err := tls.Dial("tcp", serverAddress + ":" + tcpPort, cfg)
  if err != nil {
    panic(err)
  }
  handleConn(conn)
}
