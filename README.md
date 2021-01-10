# certmin, a minimalistic certificate tool

[![Build Status](https://travis-ci.com/nxadm/certmin.svg?token=3PQd6zsu83EBNA2LAEeq&branch=main)](https://travis-ci.com/nxadm/certmin)

In short: nothing that openSSL can't do, just a few easy shortcuts (without needing openSSL). 

## Help page
```
$ ./certmin 
certmin, 0.1.0. A minimalist certificate utility.
See https://github.com/nxadm/certmin for more information.

Usage:
  certmin skim certificate1 certificate2 ...
  certmin vk certificate key
  certmin vc certificate 
    --root=ca-file1 [--root=ca-file2 ...]
    --inter=inter-file1 [--inter=inter-file2 ...]
  certmin [-h]
  certmin [-v]

Actions:
  skim         | s         : skim information from PEM certificates.
  verify-key   | vk        : verify that a PEM certificate matches an unencrypted PEM key.
  verify-chain | vc        : verify that a PEM certificate matches a PEM chain.
    --root                 : root PEM certificates to verify against (at least 1 file). 
    --inter                : intermediate PEM certificates to verify against (0 or more).
  -h           | --help    : This help message.
  -v           | --version : Version message.

```

## Examples

### Skim certificate information

```
$ ./certmin skim t/chain.crt 
Certificate file t/chain.crt:
Subject:        CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
Issuer:         CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
Serial number:  1
Not before:     2004-01-01 00:00:00 +0000 UTC
Not after:      2028-12-31 23:59:59 +0000 UTC

Subject:        CN=USERTrust RSA Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
Issuer:         CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
Serial number:  76359301477803385872276235234032301461
Not before:     2019-03-12 00:00:00 +0000 UTC
Not after:      2028-12-31 23:59:59 +0000 UTC
OCSP servers:   http://ocsp.comodoca.com

Subject:        CN=GEANT OV RSA CA 4,O=GEANT Vereniging,C=NL
Issuer:         CN=USERTrust RSA Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
Serial number:  290123421899608141648701916708796095456
Not before:     2020-02-18 00:00:00 +0000 UTC
Not after:      2033-05-01 23:59:59 +0000 UTC
OCSP servers:   http://ocsp.usertrust.com

---
```

### Verify a certificate an key match

```
$ ./certmin verify-key t/myserver.crt t/myserver.key
Certificate file t/myserver.crt and key file t/myserver.key:
certificate and key match
``` 

### Verify the chain of a certificate

```
$ ./certmin verify-chain t/myserver.crt --root t/ca.crt 
certificate is valid for the supplied chain
``` 