# certmin
![CI](https://github.com/nxadm/certmin/workflows/ci/badge.svg)[![Go Reference](https://pkg.go.dev/badge/github.com/nxadm/cmd/certmin/certmin.svg)](https://pkg.go.dev/github.com/nxadm/certmin/cmd/certmin)

`certmin` is a minimalistic certificate tool that can:
- skim (retrieve relevant human-readable information) certificates and chains,
locally or remotely.
- verify certificates against their chains, both locally or remotely. Additionally,
the chain can be generated automatically by following Issuer Certificate URLs,
even if a remote server does not offer intermediate certificates.
- verify local or remote certificates against their key.
- order chains (from leaf to root or root to leaf).
- download and/or convert certificates to PEM PKCS1 files.
- support for PEM and DER encoding in PKCS1, PKCS5, PKCS7, PKCS8 and PKCS12 containers.
- prompt for key passwords.
- colourise the output on systems that support ANSI escapes like Linux, BSDs or
MacOS, and on better terminals on MS windows like Windows Terminal (instead
of cmd.exe). Colour can be disabled with "-c".

The certmin uses the [certmin library](https://github.com/nxadm/certmin).

Binaries can be found at [releases](https://github.com/nxadm/certmin/releases)
or retrieved with go.

```
go get github.com/nxadm/certmin/cmd/certmin
```


## Help page

```
$ ./certmin
certmin, 0.5.7. A minimalist certificate utility.
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

## Examples

### Skim information

```
$ certmin skim www.google.com --follow --keep

Certificate location www.google.com:

Subject:                 CN=www.google.com,O=Google LLC,L=Mountain View,ST=California,C=US
Issuer:                  CN=GTS CA 1O1,O=Google Trust Services,C=US
Issuer Certificate URLs: http://pki.goog/gsr2/GTS1O1.crt
DNS names:               www.google.com
Serial number:           34024134475193777797945794717408234587
Version:                 3
Public key algorithm:    ECDSA
Signature algorithm:     SHA256-RSA
OCSP servers:            http://ocsp.pki.goog/gts1o1core
CRL locations:           http://crl.pki.goog/GTS1O1core.crl
Not before:              2020-12-15 14:49:26 +0000 UTC
Not after:               2021-03-09 14:49:25 +0000 UTC

Subject:                 CN=GTS CA 1O1,O=Google Trust Services,C=US
Issuer:                  CN=GlobalSign,OU=GlobalSign Root CA - R2,O=GlobalSign
Serial number:           149699596615803609916394524856
Version:                 3
Is CA:                   true
MaxPathLen is 0:         true
Public key algorithm:    RSA
Signature algorithm:     SHA256-RSA
OCSP servers:            http://ocsp.pki.goog/gsr2
CRL locations:           http://crl.pki.goog/gsr2/gsr2.crl
Not before:              2017-06-15 00:00:42 +0000 UTC
Not after:               2021-12-15 00:00:42 +0000 UTC
---

The following files were written:
certmin_www_google_com_20210121112659.crt
certmin_www_google_com_20210121112659_intermediates.crt

```

### Verify that a certificate and a key match

```
$ certmin verify-chain myserver.der --root ca.crt

Certificate location myserver.der:

certificate myserver and its chain match
---

```

### Verify the chain of a certificate

```
$ ./certmin verify-chain t/myserver.crt --root t/ca.crt
certificate CN=myserver and its chain match
```

### Verify the chain of a remote certificate

```
$ ./certmin verify-chain sectigo.com --inter chain.crt

Certificate location sectigo.com:

certificate sectigo.com and its chain match
---

```
