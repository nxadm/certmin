# certmin
![CI](https://github.com/nxadm/certmin/workflows/ci/badge.svg)[![Go Reference](https://pkg.go.dev/badge/github.com/nxadm/cmd/certmin/certmin.svg)](https://pkg.go.dev/github.com/nxadm/certmin/cmd/certmin)

Certmin is a minimalistic certificate tool that can:
- skim (retrieve relevant human-readable information) certificates and chains,
locally or remotely.
- verify certificates against their chains, both locally or remotely. Additionally,
the chain can be generated automatically by following Issuer Certificate URLs,
even if a remote server does not offer intermediate certificates.
- verify local or remote certificates against their key.
- order chains (from leaf to root or root to leaf).  
- download and/or convert certificates to PEM PKCS1 files.
- colourise the output.

The certmin uses the [certmin library](https://github.com/nxadm/certmin).

Binaries can be found at [releases](https://github.com/nxadm/certmin/releases)
or retrieved with go.

```
go get github.com/nxadm/certmin/cmd/certmin
```


## Help page
```
$ ./certmin
certmin, 0.5.0. A minimalist certificate utility.
See https://github.com/nxadm/certmin for more information.

Usage:
  certmin skim cert-location1 [cert-location2...] 
    [--leaf|--follow] [--no-roots]
    [--sort|--rsort] [--keep] [--no-colour]
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
  --keep      | -k  : write the requested certificates and chains to files
                      as PKCS1 PEM files (converting if necessary). 
  --no-colour | -c  : don't colourise the output.
  --help      | -h  : this help message.
  --version   | -v  : version message.
```

## Examples

### Skim information

```
$ ./certmin skim t/chain.crt

certificate location t/chain.crt:

Subject:                 CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
Issuer:                  CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
Serial number:           1
Version:                 3
Is CA:                   true
Public key algorithm:    RSA
Signature algorithm:     SHA1-RSA
CRL locations:           http://crl.comodoca.com/AAACertificateServices.crl, http://crl.comodo.net/AAACertificateServices.crl
Not before:              2004-01-01 00:00:00 +0000 UTC
Not after:               2028-12-31 23:59:59 +0000 UTC
                         
Subject:                 CN=USERTrust RSA Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
Issuer:                  CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
Serial number:           76359301477803385872276235234032301461
Version:                 3
Is CA:                   true
Public key algorithm:    RSA
Signature algorithm:     SHA384-RSA
OCSP servers:            http://ocsp.comodoca.com
CRL locations:           http://crl.comodoca.com/AAACertificateServices.crl
Not before:              2019-03-12 00:00:00 +0000 UTC
Not after:               2028-12-31 23:59:59 +0000 UTC
                         
Subject:                 CN=GEANT OV RSA CA 4,O=GEANT Vereniging,C=NL
Issuer:                  CN=USERTrust RSA Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
Issuer Certificate URLs: http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt
Serial number:           290123421899608141648701916708796095456
Version:                 3
Is CA:                   true
MaxPathLen is 0:         true
Public key algorithm:    RSA
Signature algorithm:     SHA384-RSA
OCSP servers:            http://ocsp.usertrust.com
CRL locations:           http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl
Not before:              2020-02-18 00:00:00 +0000 UTC
Not after:               2033-05-01 23:59:59 +0000 UTC
---

```

### Skim remote certificate information

```
$ ./certmin skim github.com --remote-chain

certificate location github.com:

Subject:                 CN=github.com,O=GitHub\, Inc.,L=San Francisco,ST=California,C=US
Issuer:                  CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
Issuer Certificate URLs: http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt
DNS names:               github.com, www.github.com
Serial number:           7101927171473588541993819712332065657
Version:                 3
Public key algorithm:    RSA
Signature algorithm:     SHA256-RSA
OCSP servers:            http://ocsp.digicert.com
CRL locations:           http://crl3.digicert.com/sha2-ha-server-g6.crl, http://crl4.digicert.com/sha2-ha-server-g6.crl
Not before:              2020-05-05 00:00:00 +0000 UTC
Not after:               2022-05-10 12:00:00 +0000 UTC
                         
Subject:                 CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
Issuer:                  CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
Serial number:           6489877074546166222510380951761917343
Version:                 3
Is CA:                   true
MaxPathLen is 0:         true
Public key algorithm:    RSA
Signature algorithm:     SHA256-RSA
OCSP servers:            http://ocsp.digicert.com
CRL locations:           http://crl4.digicert.com/DigiCertHighAssuranceEVRootCA.crl
Not before:              2013-10-22 12:00:00 +0000 UTC
Not after:               2028-10-22 12:00:00 +0000 UTC
---

```

### Skim remote certificate information using a URI scheme

```
$ ./certmin skim smtps://smtp.gmail.com

certificate location smtps://smtp.gmail.com:

Subject:                 CN=smtp.gmail.com,O=Google LLC,L=Mountain View,ST=California,C=US
Issuer:                  CN=GTS CA 1O1,O=Google Trust Services,C=US
Issuer Certificate URLs: http://pki.goog/gsr2/GTS1O1.crt
DNS names:               smtp.gmail.com
Serial number:           257235496908235390426179598999401729070
Version:                 3
Public key algorithm:    ECDSA
Signature algorithm:     SHA256-RSA
OCSP servers:            http://ocsp.pki.goog/gts1o1core
CRL locations:           http://crl.pki.goog/GTS1O1core.crl
Not before:              2020-12-15 14:48:07 +0000 UTC
Not after:               2021-03-09 14:48:06 +0000 UTC
---

```

### Verify that a certificate and a key match

```
$ ./certmin verify-key t/myserver.crt t/myserver.key
the certificate and key match
```

### Verify that a remote certificate and a key match

```
$ ./certmin verify-key myserver.com myserver.key
the certificate and key match
```

### Verify the chain of a certificate

```
$ ./certmin verify-chain t/myserver.crt --root t/ca.crt
certificate CN=myserver and its chain match
```

### Verify the chain of a remote certificate

```
$ ./certmin verify-chain github.com:443 --remote-chain
certificate CN=github.com,O=GitHub\, Inc.,L=San Francisco,ST=California,C=US and its chain match
$ ./certmin verify-chain github.com:443 --root ~/tmp/chain.crt
x509: certificate signed by unknown authority
certificate CN=github.com,O=GitHub\, Inc.,L=San Francisco,ST=California,C=US and its chain do not match
```
