# certmin, a minimalistic certificate tool

In short: nothing that openSSL can't do, just a few easy shortcuts (without needing openSSL).

Binaries can be found at [releases](https://github.com/nxadm/certmin/releases)
or retrieved with go.

```
go get github.com/nxadm/certmin
```


## Help page
```
$ ./certmin
certmin, 0.2.0. A minimalist certificate utility.
See https://github.com/nxadm/certmin for more information.

Usage:
  certmin skim [--tcp|--udp] [--remote-chain] cert-location1 cert-location2...
  certmin vk   [--tcp|--udp] cert-location key-file
  certmin vc   [--tcp|--udp] [--remote-chain] cert-location 
    --root=ca-file1 [--root=ca-file2 ...]
    --inter=inter-file1 [--inter=inter-file2 ...]
  certmin [-h]
  certmin [-v]

Actions:
  skim         | sc        : skim PEM certificate files (including bundles)
							 and show information.
    --remote-chain         : also retrieve the chain (if offered) when
							 retrieving remote certificates (--tcp or --udp).

  verify-key   | vk        : verify that a PEM certificate and unencrypted key
                             match.

  verify-chain | vc        : verify that a PEM certificate matches its chain.
    --remote-chain         : match against the chain remotely retrieved with
							 the certificate.
    --root                 : root PEM certificate file to verify against (at
                             least 1 file if not remotely retrieved). 
    --inter                : intermediate PEM certificates files to verify
                             against (0 or more).

Global options:
  --tcp                    : retrieve the certificate files through TCP
                             (format "hostname:port"). 
  --udp                    : retrieve the certificate files through UDP
                             (format "hostname:port").
  -h           | --help    : This help message.
  -v           | --version : Version message.
```

## Examples

### Skim local certificate information

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

### Verify that a certificate and a key match

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
