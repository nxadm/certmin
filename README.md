# certmin
![CI](https://github.com/nxadm/certmin/workflows/ci/badge.svg)[![Go Reference](https://pkg.go.dev/badge/github.com/nxadm/certmin.svg)](https://pkg.go.dev/github.com/nxadm/certmin)

## Description

certmin is a small, minimalistic library with high level functions
for X509 certificates (SSL). It supports certificates and keys with 
PEM and DER encoding in PKCS1, PKCS5, PKCS7, PKCS8 and PKCS12
containers. Available functions include decoding and encoding of
certificates and keys, verify certificates against chains and
verify a certificate against a key. Utilities include checking 
if a cert is a root CA, split certs in intermediates and roots and
retrieving of certificates and chains.

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

Read the API documentation at [pkg.go.dev](https://pkg.go.dev/github.com/nxadm/certmin).
