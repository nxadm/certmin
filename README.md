# certmin
![CI](https://github.com/nxadm/certmin/workflows/ci/badge.svg)[![Go Reference](https://pkg.go.dev/badge/github.com/nxadm/certmin.svg)](https://pkg.go.dev/github.com/nxadm/certmin)

## Description

certmin is a small, minimalistic library with high level functions
for X509 certificates (SSL). It supports certificates and keys with 
PEM and DER encoding in PKCS1, PKCS5, PKCS7, PKCS8 and PKCS12
containers.

## Installation

certmin is available using the standard `go get` command.

Install by running:

    go get github.com/nxadm/certmin

## Usage

certmin van be loaded by a regular import:

``` go
import flag "github.com/nxadm/certmin"
```

## API

The documentation can be also read at [pkg.go.dev](https://pkg.go.dev/github.com/nxadm/certmin).

### Types

```go
type CertTree struct {
Certificate          *x509.Certificate
Intermediates, Roots []*x509.Certificate
}
```
CertTree represents a chain where certificates are assigned as a
Certificate, Intermediates and Roots.


### Functions

```go
func DecodeCertBytes(certBytes []byte, password string) (
	[]*x509.Certificate, error)
```
DecodeCertBytes reads a []byte with DER or PEM PKCS1, PKCS7 and PKCS12
encoded certificates, and returns the contents as a []*x509.Certificate and
an error if encountered. A password is only needed for PKCS12.


```go
func DecodeCertBytesPKCS12(certBytes []byte, password string) (
	[]*x509.Certificate, error)
```
DecodeCertBytesPKCS12 reads a []byte with PKCS12 encoded certificates (e.g.
read from a file of a HTTP response body) and a password. It returns the
contents as a []*x509.Certificate and an error if encountered. If you don't
know in what format the data is encoded, use DecodeCertBytes.

```go
func DecodeCertBytesPKCS1DER(certBytes []byte) (
	[]*x509.Certificate, error)
```
DecodeCertBytesPKCS1DER reads a []byte with PKCS1 DER encoded certificates
(e.g. read from a file of a HTTP response body), and returns the contents as
a []*x509.Certificate and an error if encountered. If you don't know in what
format the data is encoded, use DecodeCertBytes.

```go
func DecodeCertBytesPKCS1PEM(certBytes []byte) (
	[]*x509.Certificate, error)
```
DecodeCertBytesPKCS1PEM reads a []byte with PKCS1 PEM encoded certificates
(e.g. read from a file of a HTTP response body), and returns the contents as
a []*x509.Certificate and an error if encountered. If you don't know in what
format the data is encoded, use DecodeCertBytes.

```go
func DecodeCertBytesPKCS7DER(certBytes []byte) (
	[]*x509.Certificate, error)
```
DecodeCertBytesPKCS7DER reads a []byte with PKCS7 DER encoded certificates
(e.g. read from a file of a HTTP response body), and returns the contents as
a []*x509.Certificate and an error if encountered. If you don't know in what
format the data is encoded, use DecodeCertBytes.

```go
func DecodeCertBytesPKCS7PEM(certBytes []byte) (
	[]*x509.Certificate, error)
```
DecodeCertBytesPKCS7PEM reads a []byte with PKCS7 PEM encoded certificates
(e.g. read from a file of a HTTP response body), and returns the contents as
a []*x509.Certificate and an error if encountered. If you don't know in what
format the data is encoded, use DecodeCertBytes.

```go
func DecodeCertFile(certFile, password string) (
	[]*x509.Certificate, error)
```
DecodeCertFile reads a file with DER or PEM encoded certificates and returns
the contents as a []*x509.Certificate and an error if encountered.

```go
func DecodeKeyBytes(keyBytes []byte, password string) (
    *pem.Block, error)
```
DecodeKeyBytes reads a []byte with a key and returns a *pem.Block and an
error if encountered.

```go
func DecodeKeyBytesPKCS1(keyBytes []byte) (
    *pem.Block, error)
```
DecodeKeyBytesPKCS1 reads a []byte with a PKCS1 PEM encoded key and returns
a *pem.Block and an error if encountered. If you don't know in what format
the data is encoded, use DecodeKeyBytes.

```go
func DecodeKeyBytesPKCS12(keyBytes []byte, password string) (
	*pem.Block, error)
```
DecodeKeyBytesPKCS12 reads a []byte with an encrypted PKCS12 encoded key and
returns a *pem.Block and an error if encountered. If you don't know in what
format the data is encoded, use DecodeKeyBytes.

```go
func DecodeKeyBytesPKCS8(keyBytes []byte, password string) (
	*pem.Block, error)
```
DecodeKeyBytesPKCS8 reads a []byte with an encrypted PKCS8 PEM encoded key
and returns a *pem.Block and an error if encountered. If you don't know in
what format the data is encoded, use DecodeKeyBytes.

```go
func DecodeKeyFile(keyFile string, password string) (
	*pem.Block, error)
```
DecodeKeyFile reads a file with PEM encoded key and returns the contents as
a *pem.Block and an error if encountered.

```go
func EncodeCertAsPKCS1PEM(cert *x509.Certificate) (
    []byte, error)
```
EncodeCertAsPKCS1PEM converts *x509.Certificate to a []byte with data
encoded as PKCS1 PEM and an error.

```go
func EncodeKeyAsPKCS1PEM(key *pem.Block) (
	[]byte, error)
```
EncodeKeyAsPKCS1PEM converts *pem.Block private key to a []byte with data
encoded as PKCS1 PEM and an error.

```go
func IsRootCA(cert *x509.Certificate) bool
```
IsRootCA returns for a given *x509.Certificate true if the CA is marked as
IsCA and the Subject and the Issuer are the same.

```go
func RetrieveCertsFromAddr(addr string, timeOut time.Duration) (
	[]*x509.Certificate, error, error)
```
RetrieveCertsFromAddr retrieves all the certificates offered by the remote
host. As parameters it takes an address string in the form of hostname:port
and a time-out duration for the connection. The time-out is used for both
the TCP and the SSL connection, with 0 disabling it. The return values are a
[]*x509.Certificate (with the first element being the certificate of the
server), an error with a warning (e.g. mismatch between the hostname and the
CN or DNS alias in the certificate) and an error in case of failure.

```go
func RetrieveChainFromIssuerURLs(cert *x509.Certificate, 
	timeOut time.Duration) ([]*x509.Certificate, error)
```
RetrieveChainFromIssuerURLs retrieves the chain for a certificate by
following the Issuing Certificate URLs field in the certificate (if present)
and consecutively following the Issuing Certificate URLs from issuing
certificates. As parameters it takes a *x509.Certificate and a time-out
duration for the HTTP connection with 0 disabling it. The return values are
a []*x509.Certificate (with the first element being the supplied
certificate) and an error in case of failure.

```go
func SplitCertsAsTree(certs []*x509.Certificate) *CertTree
```
SplitCertsAsTree returns a *CertTree where the given certificates are
assigned as Certificate, Intermediates and Roots. The starting leaf
certificate must be the first element of the given []*x509.Certificate.
