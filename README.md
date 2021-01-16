# certmin, a minimalistic certificate tool

In short: nothing that openSSL can't do, just a few easy shortcuts (without needing openSSL) and colourised output.

Binaries can be found at [releases](https://github.com/nxadm/certmin/releases)
or retrieved with go.

```
go get github.com/nxadm/certmin
```


## Help page
```
$ ./certmin
certmin, 0.4.1. A minimalist certificate utility.
See https://github.com/nxadm/certmin for more information.

Usage:
  certmin skim cert-location1 [cert-location2...] 
	 [--remote-chain] [--remote-inters] [--no-colour] 
  certmin verify-key cert-location key-file [--no-colour]
  certmin verify-chain cert-location [cert-location2...]
	[--remote-chain] [--remote-inters] 
    [--root=ca-file1 --root=ca-file2...]
    [--inter=inter-file1 --inter=inter-file2...]
    [--no-colour]
  certmin [-h]
  certmin [-v]

Certificate locations can be a file, a string in the form of
hostname:port (default 443 if not :port supplied) or an URL.
When verifying a chain, the OS trust store will be used if
if no roots certificates are given or requested. 

Actions:
  skim | sc         : skim PEM certificates (including bundles)
                      and show information.
    --remote-chain  : retrieve the chain (if offered) for
                      remote certificates.

  verify-key | vk   : verify that a PEM certificate and
                      key match.

  verify-chain | vc : verify that a PEM certificate matches its
                      chain.
    --remote-chain  : retrieve the chain (if offered) for
                      remote certificates.
    --remote-inters : retrieve the chain (if offered) for
                      remote certificates, without root CAs.
    --root          : root PEM certificate file to verify.
                      against (optional). 
    --inter         : intermediate PEM certificates files
                      to verify against (optional).

Global options:
  --no-colour | -c : don't colourise the output'
  --help      | -h : this help message.
  --version   | -v : version message.
```

## Examples

### Skim local certificate information

```
$ ./certmin skim t/chain.crt
 
certificate location t/chain.crt:

Subject:                CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
Issuer:                 CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
Serial number:          1
Public key algorithm:   RSA
Signature algorithm:    SHA1-RSA
CRL locations:          http://crl.comodoca.com/AAACertificateServices.crl, http://crl.comodo.net/AAACertificateServices.crl
Not before:             2004-01-01 00:00:00 +0000 UTC
Not after:              2028-12-31 23:59:59 +0000 UTC

Subject:                CN=USERTrust RSA Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
Issuer:                 CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
Serial number:          76359301477803385872276235234032301461
Public key algorithm:   RSA
Signature algorithm:    SHA384-RSA
OCSP servers:           http://ocsp.comodoca.com
CRL locations:          http://crl.comodoca.com/AAACertificateServices.crl
Not before:             2019-03-12 00:00:00 +0000 UTC
Not after:              2028-12-31 23:59:59 +0000 UTC

Subject:                CN=GEANT OV RSA CA 4,O=GEANT Vereniging,C=NL
Issuer:                 CN=USERTrust RSA Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
Serial number:          290123421899608141648701916708796095456
Public key algorithm:   RSA
Signature algorithm:    SHA384-RSA
OCSP servers:           http://ocsp.usertrust.com
CRL locations:          http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl
Not before:             2020-02-18 00:00:00 +0000 UTC
Not after:              2033-05-01 23:59:59 +0000 UTC

---
```

### Skim remote certificate information

```
$ ./certmin skim github.com --remote-chain
Certificate location github.com:
Subject:                CN=github.com,O=GitHub\, Inc.,L=San Francisco,ST=California,C=US
Issuer:                 CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
DNS names:              github.com, www.github.com
Is CA:                  false  
Serial number:          7101927171473588541993819712332065657
Public key algorithm:   RSA
Signature algorithm:    SHA256-RSA
OCSP servers:           http://ocsp.digicert.com
CRL locations:          http://crl3.digicert.com/sha2-ha-server-g6.crl, http://crl4.digicert.com/sha2-ha-server-g6.crl
Not before:             2020-05-05 00:00:00 +0000 UTC
Not after:              2022-05-10 12:00:00 +0000 UTC

Subject:                CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
Issuer:                 CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
Is CA:                  true
Serial number:          6489877074546166222510380951761917343
Public key algorithm:   RSA
Signature algorithm:    SHA256-RSA
OCSP servers:           http://ocsp.digicert.com
CRL locations:          http://crl4.digicert.com/DigiCertHighAssuranceEVRootCA.crl
Not before:             2013-10-22 12:00:00 +0000 UTC
Not after:              2028-10-22 12:00:00 +0000 UTC

---
```

### Skim remote certificate information using a URI scheme

```
$ ./certmin skim smtps://smtp.gmail.com
Certificate location smtps://smtp.gmail.com:
Subject:                CN=smtp.gmail.com,O=Google LLC,L=Mountain View,ST=California,C=US
Issuer:                 CN=GTS CA 1O1,O=Google Trust Services,C=US
DNS names:              smtp.gmail.com
Serial number:          257235496908235390426179598999401729070
Public key algorithm:   ECDSA
Signature algorithm:    SHA256-RSA
OCSP servers:           http://ocsp.pki.goog/gts1o1core
CRL locations:          http://crl.pki.goog/GTS1O1core.crl
Not before:             2020-12-15 14:48:07 +0000 UTC
Not after:              2021-03-09 14:48:06 +0000 UTC

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