# certmin
![CI](https://github.com/nxadm/certmin/workflows/ci/badge.svg)[![Go Reference](https://pkg.go.dev/badge/github.com/nxadm/certmin.svg)](https://pkg.go.dev/github.com/nxadm/certmin)

## Description

certmin is a small, minimalistic library with high level functions
for X509 certificates (SSL). It supports certificates and keys with 
PEM and DER encoding in PKCS1, PKCS5, PKCS7, PKCS8 and PKCS12
containers. Available functions include decoding and encoding of
certificates and keys, verify certificates against chains and
verify a certificate against a key. Utilities include checking 
if a cert is a root CA, finding the leaf certificate,  split certs,
sort chains in intermediates and roots and retrieving of certificates
and chains. See: [API documentation at pkg.go.dev](https://pkg.go.dev/github.com/nxadm/certmin).

There is also a companion [certmin CLI application](https://github.com/nxadm/certmin/cmd/certmin)
that consumes many of the functionalities of the library:

```
$ ./certmin
certmin, 0.5.9. A minimalist certificate utility.
See https://github.com/nxadm/certmin for more information.

Usage:
  certmin skim cert-location1 [cert-location2...] 
    [--leaf|--follow] [--no-roots]
    [--sort|--rsort] [--once] [--keep] [--no-colour]
  certmin verify-chain cert-location [cert-location2...]
    [--root=ca-file1 --root=ca-file2...]
    [--inter=inter-file1 --inter=inter-file2...]
    [--leaf|--follow] [--no-roots]
    [--sort|--rsort] [--keep] [--no-colour]
  certmin verify-key key-file cert-location1 [cert-location2...]
    [--keep] [--no-colour]
  certmin [-h]
  certmin [-v]

Certificate locations can be local files or remote addresses. Remote locations
can be a hostname with optionally a port attached by ":" (defaults to port
443) or an URL (scheme://hostname for known schemes like https, ldaps, smtps,
etc. or scheme://hostname:port for non-standard ports). When verifying a
chain, the OS trust store will be used if no roots certificates are given as
files or remotely requested. 

Actions:
  skim         | sc : skim certificates (including bundles).
  verify-chain | vc : match certificates again its chain(s).
  verify-key   | vk : match keys against certificate(s).

Global options (optional):
  --leaf      | -l  : show only the local or remote leaf, not the chain.
  --no-roots  | -n  : don't retrieve root certificates.
  --follow    | -f  : follow Issuer Certificate URIs to retrieve chain.
  --root      | -r  : root certificate file(s).
  --inter     | -i  : intermediate certificate file(s).
  --sort      | -s  : sort the certificates and chains from leaf to root.
  --rsort     | -z  : sort the certificates and chains from root to leaf.
  --once      | -o  : if within a location several certificates share an
                      intermediate/root, don't show certificates more than
                      once to visually complete the chain. If "rsort" not
                      given it enables "sort".  
  --keep      | -k  : write the requested certificates and chains to files
                      as PKCS1 PEM files (converting if necessary). 
  --no-colour | -c  : don't colourise the output.
  --help      | -h  : this help message.
  --version   | -v  : version message.
```

## Installation

certmin is available using the standard `go get` command.

Install by running:

    go get github.com/nxadm/certmin
   
The CLI tool can be installed by running:

    go get github.com/nxadm/certmin/cmd/certmin

## Usage

certmin can be loaded by a regular import:

``` go
import "github.com/nxadm/certmin"
```

## API

Read the API documentation at [pkg.go.dev](https://pkg.go.dev/github.com/nxadm/certmin).
