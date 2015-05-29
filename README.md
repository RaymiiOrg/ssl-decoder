# SSL Decoder

Simple PHP script which decodes an SSL connection and/or certificate and displays information.

* Tries to give all the information you need instead of a rating. 
* Open source, so you can self host it. 
* Shows the entire certificate chain. 
* Allows to paste a CRL/Cert
* Validates the certificate, chain, CRL and OCSP (of every cert in the chain)
* Has easy copy-pastable PEM versions of certs
* Ciphersuite enumeration as an option.
* JSON API
* Fast.

## Features

- Connection information
- Decodes CSR
- Decodes Certificates
- Decodes SSL Connections
- SSL Protocol version tester
- OCSP validation
- OCSP Stapling
- HSTS & HPKP headers
- SPKI hash
- Public Key PEM
- Certificate PEM
- CRL validation
- Full certificate chain validation.
- Issuer validation
- Date validation
- JSON API
- Warnings for bad connection settings or certificate options
- Heartbleed test
- SNI specific testing

## Requirements

- PHP 5.6+
- OpenSSL
- PHP must allow shell_exec and remote fopen.
- Debian: `php-intl` package installed.

For the heartbleed test `python2` and `python-netaddr` are required.

## Installation

Unpack and go!

    cd /var/www
    git clone https://github.com/RaymiiOrg/ssl-decoder.git
    chown $wwwuser ssl-decoder/results/

Browse to https://your-server/ssl-decoder.

The default timeout for checks is 2 seconds. If this is to fast for your internal services, this can be raised in the `variables.php` file.

### OpenSSL compilation

If you want to use the latest OpenSSL and your distro doesn't ship with it, you can compile your own OpenSSL and replace the system one. Do note that this might break stuff.

    cd /usr/local/src
    wget https://openssl.org/source/openssl-1.0.2.tar.gz
    tar -xf openssl-1.0.2.tar.gz
    cd openssl-1.0.2
    ./config --prefix=/usr --openssldir=/usr/local/openssl shared zlib
    make
    make test
    make install

## Demo

See [https://tls.so](https://tls.so).

<a href="https://tls.so"><img src="http://i.imgur.com/R1BQlLVm.png" /></a>

### License

GNU Affero GPL v3: [https://www.gnu.org/licenses/agpl-3.0.html](https://www.gnu.org/licenses/agpl-3.0.html)


### Tracking

The SSL Decoder includes Piwik Javascript tracking code. If you self host it, you might want to remove that. It is in `inc/footer.php`.

### JSON API

Endpoint: `/json.php`. 


Accepts: 
- CSR 
- Certificate 
- Host:ip (+port, default 443)

Returns JSON UTF-8 encoded certificate (and connection) data. 

Add `type=pretty` as parameter to get a pretty printed JSON (text/html). Otherwise just JSON (application/json).

Examples:

#### CSR

Params:

    - `csr` = PEM encoded certificate request

Example Request:

    json.php?csr=-----BEGIN+CERTIFICATE+REQUEST-----+%0D%0AMIIG8zCCBpgCAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx+%0D%0AITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCBkgwggQ6BgcqhkjO+%0D%0AOAQBMIIELQKCAgEA5KY342mozvKAAICT4EXDMfnDw7HkribKi8vMy%2BHQXJ%2FhAoNs+%0D%0AByxZygZVc48Q0FA1wMcFC20RtdswMCuogBlUcNxmOCZe%2FmYIJxfp6EWi6ZG0vTA5+%0D%0An6a89iEnfgZ9s2xnhO%2FXiHFax8cjHujQPH3epAtVsBPoxIHsWtVZv%2Fp08L6xgSHl%0D%0AwCQB00fuAhWu60oF45vsQwD%2FvPtQnYFD2elDWivcz51YT8c9EyiXb6geHhGSJkAY%0D%0AVEXNPV7%2FMrAF9ufhc9ss9vrxRiAvBEW2KToL8%2FcYa%2B1L0%2FVEGgJ8jkhhSfiN2q13%0D%0A%2FwBMgG%2FKPr5v94qjeuM4fl6LPZqOjhoYTJJL3WWiAiUzMez30hz%2BE1TUe5f9VI%2Ba%0D%0A1BH%2FhFvlDhuIEyIfsmupzKf0RpzXbSkP%2F4v3PlOuiuOEza1mbZZSOXBGOdKYYC7K%0D%0ALtVb62MD0B%2FFvD8yKO5NQCwFbQC60tU6JyneJJFdqY0HUjHERC3FMDoXoEH%2Fv8b5%0D%0A93kDg8jvmwijh96HgxkssoiRxYp9a9IL%2BGQ1WYYtVTSCz8zgWZyo0W0%2B3bJ66oAg%0D%0Al%2BfZw98xSa0SG1bd8k4c6xVgp%2Bou3EPorbXdgZg31HKrbiFVuhuJFvP3fRHw2GGM%0D%0A9oyFdAGuf1mdQU4XwqoEmhcRnIkN4IF8aMz7VEawAbLgNmu8E9bWIrEjMCkCIQDv%0D%0AQXTIsw1pCZXmF6Yum2%2FgP6xqbCuL6Te4q7KQrPYTyQKCAgEAooejkz2e%2BfnMKnIM%0D%0AK1xMcR8%2FgnD0HDPnhZ5WSwEl%2BalDjAl1U15BdcjIFL%2FdpCRn6JwuM2uY3wtyVU6i%0D%0A2iW4dXsP7rkh2jZP008MQc1e2OrqscGgqpHwJyZa14bUDMbCp2rVYaR2IxLOKa98%0D%0AvbTq8YOBwT1rml1yUYoQHRoU5sFLomfqZILEfomx9w%2FSS9HH6iUYX6AGrGFi9Dqc%0D%0AyOrzkUYFh7c5JSLzvt8I2Q8hZMDz%2FUwuHkfQ%2FjUDZXtazUOhAjxUfvYDYqCMF%2F7R%0D%0AZPjkpo0yX8Rb13J50%2BUuPfOvrWl6nnK%2BNN8Y%2FRIBzaEvEsq6%2BH6mf0J3XFVGtIPy%0D%0AIulMe5iyTwyvdUHxxZzWjRY9apPw6Laoen4yK5D6IrqY2QCGvWZHgfa41raQEKtq%0D%0AXuubALxOtBxehEansfB2g7hY%2BNfFk0BskswhVqJw6EoLUJKPijXY9Kms%2FANXRpto%0D%0Au0Qzv76YZfJwg%2Faidowoewp%2B7cBAGZbRg1gcGU%2Fe9cFqmruwgy%2Bs2p6t3GamgSRn%0D%0AdwNCOe0R0UjdjZaieJLu6EkZK%2BdhcDXvlVd%2FRx2Vq62zKgYawvIsctdseUAs%2BGf6%0D%0Ajweb38m1uCyIyUkMrOH9GnxCkyiUAH05UJAXT3%2FhhS4sra6A74K%2BAF8wlpfxYY38%0D%0Aquo1Ai%2Bc9MBg%2FKWIVQrsinDI%2BKUDggIGAAKCAgEAkXIvCerLlpA%2FTP7joo0ruxkr%0D%0AGaHa0g0xLJp89r1eRbyzlZZPgsq1AqCfp0%2B2TYAe%2FZsn0Xs4R9n7S5lXIhKEO4YM%0D%0ACIOdWMCZL%2FZoeMzEv8ievxBoFLUQNMzTnRS9lOhaC3ew9JjQMszM5wRAtrdCVgnG%0D%0ACxWD4JC9okn%2F%2BnTSE5exLda%2FQ8BpXzKUuWSJaGYt1H1pRsUXsx0apZ2u%2FRyq6aI4%0D%0A2HwOKZN0%2FPV%2FoHQ8ayxu22dbfduY7YJ4zMkeovggR6tAoOKw4%2BxMMy82DKxpa%2Fkt%0D%0A5a%2B26Myf2dkzHH6ndgupjde%2FsZUifoJMib6i33DdT3TPwiJ1QvCK7cTlgO9CzeIZ%0D%0AssPBYC%2FfpV65Ih9wWJPaObDQPA5tt%2BtKTMOKwz9jmiaXFhmlGZtCahfll5xWXzVJ%0D%0AFbM6NxgYg0bErRcyck8Ngc5%2BO8fm3oGSotQ7eVh%2B%2B04J5g3vk9ufqbi02mFlpMZi%0D%0A%2FFykgQYbnCen%2BBxcO%2BboUMd4urqL0VpSu5NtBd8%2BqULWRrvBEf8s2IY3OaOQEvwJ%0D%0ANZhWJdNpg2lY%2BUmefxm9P9qQqfIhJ3LZavr3jfy81xVFqOciO1Xt7TfzVFqMGH1s%0D%0AaKyPCpApJQ%2BWPuM1WiAimGJFUgk5ZwHyqC8NFDA5wSr%2BfYR6NxZv3pFscb3PqxpQ%0D%0A6C%2BjnKYiyibu4indeE6gADALBglghkgBZQMEAwIDSAAwRQIgMvqOm1M55K0mNYL2%0D%0ArtHl2W%2F1zJufX7FlpAlR3UgoqdICIQDQoyoS8ND%2BjSUl1Pbn%2Buh6yzglP3vfvyxB%0D%0Ax1%2BT5MCUKw%3D%3D%0D%0A-----END+CERTIFICATE+REQUEST-----

Response

       {
        "data": {
            "chain": {
                "1": {
                    "subject": {
                        "C": "AU",
                        "ST": "Some-State",
                        "O": "Internet Widgits Pty Ltd"
                    },
                    "key": "-----BEGIN PUBLIC KEY-----\nMIIGS[...]LKJu7iKd14Tg==\n-----END PUBLIC KEY-----\n",
                    "details": {
                        "bits": "4096",
                        "key": "-----BEGIN PUBLIC KEY-----\nMIIGS[...]LKJu7iKd14Tg==\n-----END PUBLIC KEY-----\n",
                        "dsa": {
                            "p": "...",
                            "q": "...",
                            "pub_key": "..."
                        },
                        "type": "1"
                    }
                }
            }
        }
    }


#### Certificate 

Params:

    - `csr` = PEM encoded certificate

Example Request:

    json.php?csr=-----BEGIN+CERTIFICATE-----%0D%0AMIIKmDCCBoCgAwIBAgIBAzANBgkqhkiG9w0BAQUFADCBgjELMAkGA1UEBhMCTkwx%0D%0AFTATBgNVBAgMDFp1aWQgSG9sbGFuZDESMBAGA1UEBwwJUm90dGVyZGFtMRowGAYD%0D%0AVQQKDBFTcGFya2xpbmcgTmV0d29yazEVMBMGA1UECwwMU3BhcmtsaW5nIENBMRUw%0D%0AEwYDVQQDDAxTcGFya2xpbmcgQ0EwHhcNMTUwMzI5MTExMzU4WhcNMTcwMzI4MTEx%0D%0AMzU4WjBvMRMwEQYDVQQDDApnb29nbGUuY29tMRIwEAYDVQQIDAlSb3R0ZXJkYW0x%0D%0ACzAJBgNVBAYTAk5MMRowGAYDVQQKDBFTcGFya2xpbmcgTmV0d29yazEbMBkGA1UE%0D%0ACwwSU3BhcmtsaW5nIFdlYnNpdGVzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC%0D%0ACgKCAgEAoi3dJz7UcdbIU%2BfM5S44tk8MM%2B%2BPguUDVnC2wviFgpg6Q%2BINGnAofUoe%0D%0Ay%2BCtiqNWZyey0QO9AglEX8Q0z3eTSTf29ntBgfMUwpMkkXuXDrdH78%2Fzh83L4VkO%0D%0Ar%2B87cRZi4clskcIE1DJrw%2FbN9oyRAjWdKZfpaMtLT9ab4yWNOCqy0gzxiG7NfAfv%0D%0AvqxF6Rwg9lNVJmRqwxP54qa2ayjmqVPhBgLqpRRfE2CPxxiCb8KdYhbFVaEraXKM%0D%0ARMFans%2BXSD6I5e0N3BTjAf2%2Bv6Dzjyt9sQFh%2FEpjqZrTe2JCwg3C44hy8RdohuN%2B%0D%0At0OsvAO46Xk7cP8Z%2FhqxSpcvNRhcjFQ6bCv74OXInVu5pSHydARSlM0FKfhAjaVl%0D%0Acu9Q%2FpkQ2rhFtvpKnJr%2B3tZiSlRpuK0MLDLMhgWopfMzXvBAzSxDC0hXODzjHA0M%0D%0AoTbW4vDmAv6bn%2BJXzxHsaxjkbpr1x2FRbwj8ZuwIzUIZP46iRVzZ97p%2B6D9LK40q%0D%0AhI50eiuFQfigqXoe5BrniQtkZi293H4dKJzvoLSAbjYB0PLD6I7zkNt8QtVDLhSz%0D%0A5u7fC890VYK9DZZP1B8RAYn91SRRFBBnJDSRgvutA%2FRSkXkLXviCw4oDIfijTrg4%0D%0AW35ASS5LjAOwbucKY3lsbd2lbLGcyxro9Z9aeLxZEX49X3u1dhUCAwEAAaOCAykw%0D%0AggMlMA8GA1UdEwEB%2FwQFMAMBAf8wHQYDVR0OBBYEFK8Cti%2BdB4641gUmn048XvPu%0D%0AhCs0MB8GA1UdIwQYMBaAFKyJWGQeqG3MO7k4TliuqefL7do3MAsGA1UdDwQEAwIF%0D%0AoDATBgNVHSUEDDAKBggrBgEFBQcDATCCASQGA1UdHwSCARswggEXMEmgR6BFhkNo%0D%0AdHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9SU0FEb21haW5WYWxpZGF0aW9u%0D%0AU2VjdXJlU2VydmVyQ0EuY3JsMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNv%0D%0AbS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDA0oDKgMIYuaHR0%0D%0AcDovL2NybC5wa2lvdmVyaGVpZC5ubC9Sb290TGF0ZXN0Q1JMLUcyLmNybDAgoB6g%0D%0AHIYaaHR0cDovL3NyLnN5bWNiLmNvbS9zci5jcmwwL6AtoCuGKWh0dHA6Ly9jcmwu%0D%0AdGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3JsMFEGA1UdEQRKMEiCCyouZ29v%0D%0AZ2xlLm5sggpnb29nbGUuY29tggwqLmdvb2dsZS5jb22CBSouY29tggpyYXltaWku%0D%0Ab3JnggwqLnJheW1paS5vcmcwggEzBggrBgEFBQcBAQSCASUwggEhME8GCCsGAQUF%0D%0ABzAChkNodHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9DT01PRE9SU0FEb21haW5WYWxp%0D%0AZGF0aW9uU2VjdXJlU2VydmVyQ0EuY3J0MCYGCCsGAQUFBzAChhpodHRwOi8vc3Iu%0D%0Ac3ltY2IuY29tL3NyLmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2Rv%0D%0AY2EuY29tMDcGCCsGAQUFBzABhitodHRwOi8vb2NzcC5kaWdpZGVudGl0eS5ldS9M%0D%0ANC9zZXJ2aWNlcy9vY3NwMB8GCCsGAQUFBzABhhNodHRwOi8vc3Iuc3ltY2QuY29t%0D%0AMCYGCCsGAQUFBzABhhpodHRwOi8vb2NzcC50Y3MudGVyZW5hLm9yZzANBgkqhkiG%0D%0A9w0BAQUFAAOCBAEAWM5iu%2F7PUCJyhN3nR77FxCWanLeAIWU8NJEpspjZgjH5j0Oc%0D%0A8mqYmJEzfrIg4O%2F9ZoqrUV1OiDW7fyf7DHW9yTwmcc%2Fwute05TRN3dtUXmzNMk6B%0D%0ABfaBbwuXjL8ZEZcZnHKSvWxMmqG2Rx3csA68I53qluedP2b61dQiTwiBa1SH4v3G%0D%0A78ZeJi03RSoB6Fbn6l%2BcIfPNI877d%2BpzOvBs05Vj57bdb%2B7Ji0lzDWQNV7uuc3%2FR%0D%0AWVEfZv0ErBgVxlI3EautBQaGZCf1ltwyo2n8wTkVou6wFIX5K4LkWOYuSiu%2FcgB3%0D%0A%2BOl21TGZf%2BoqhMCkmYp313MSbu8HUO7COpJI0B4IZ4Zm%2BYelKGjhDX8bx5l4TrGh%0D%0AfbsuoHpesRx3%2FzEnoP4VGAkuN7H5PALhF3G%2FRI8jKwBdLA3ANhochqsICmvu9Li2%0D%0ASJAxT87%2Fh4azUYGvd9ZnEWl5rMSqZkFtZhw0y%2FPVKgw0rXuaVfvqqSuETeq6gGp1%0D%0ALYtJUq4LO4Yvg7QXxa1qCeZmTbea%2BQmE%2BWsi0jPYQ3LkLkOpDh9nsuY3Ru7f%2BgIB%0D%0AdELs2TTpOKcg7eKLEpv8JGLXv0NYwc1aqKyL6jycjeGCC9riw8Xla3ZLgAx4IJyM%0D%0AJV7qRUxg4jMK%2BpQd5q1Z3RX5PIwPdzFkHdBnPH6k7GCOqEzQnmR8Hql9xUwi5svM%0D%0AiitX4Y7FbXW1zxzaBX6SLCfE60lUhSh7ik%2Bb9TK77Gg%2FuLDmdanXpFguSezGCHZ2%0D%0AjL4mYLeXWV88WVXEH4tmXsCQrQsmnlcTAJpvXW7NvV8lCjqh3RbXXG7RHd2IEWfr%0D%0AZAAaT%2BnwNIW%2Fx8mXJxUx9RpCKVS%2BCm8Q%2FjDHT9X7DxdHlzzzvN%2Brv8yy6P%2Fp8HGP%0D%0AY84H84qVP9uQgoAxArKRIVIO7ZjaT38V5tlidTxjyf38y0E%2FHV%2BLM2vjl3wsefQw%0D%0AU8dzNGCNvEWycVrBrZArjITkHFMq%2F3VUODlX4M3GTZ4XuZR%2BEGB0kF3uyApE%2FfLX%0D%0AP4qzfsTw%2F0p0Xn7K%2Ff3HsYyyXbh17sR761gbQCXHJN1YE0F5U4F7DESgbhWZrLJ6%0D%0AtCG5Np%2FmrQ7rKIJxKqSdSKicKYgi0lSk0bq9eF0QLDvECiCiEDT33D8ju%2BKjPXie%0D%0Ad6bddv3wUguPUOg7hYr1DLaRwZ9FtfM2UqYtEQxwuebDragUY2gO0tT2wtqNFhwl%0D%0AXnPFJhWi3Atz%2FcjvdlktvhhaqHJLUkmaXVsgys470rUUq%2BJETCUVM8dKYfC3Nir1%0D%0APcl%2Bic8lyHLRserIynKLsnYlCgMb6DdbyMXWUUe2OGuUvz9OI09VjY8vAnKfM0E0%0D%0AQ3aqS6U2xoswso%2Bov1HkVOOlcNFpJAqQ7pn4iA%3D%3D%0D%0A-----END+CERTIFICATE-----%0D%0A

Example Response:

    {
        "data": {
            "chain": {
                "1": {
                    "cert_data": {
                        "name": "/CN=google.com/ST=Rotterdam/C=NL/O=Sparkling Network/OU=Sparkling Websites",
                        "subject": {
                            "CN": "google.com",
                            "ST": "Rotterdam",
                            "C": "NL",
                            "O": "Sparkling Network",
                            "OU": "Sparkling Websites"
                        },
                        "hash": "ceef4183",
                        "issuer": {
                            "C": "NL",
                            "ST": "Zuid Holland",
                            "L": "Rotterdam",
                            "O": "Sparkling Network",
                            "OU": "Sparkling CA",
                            "CN": "Sparkling CA"
                        },
                        "version": "2",
                        "serialNumber": "3",
                        "validFrom": "150329111358Z",
                        "validTo": "170328111358Z",
                        "validFrom_time_t": "1427627638",
                        "validTo_time_t": "1490699638",
                        "extensions": {
                            "basicConstraints": "CA:TRUE",
                            "subjectKeyIdentifier": "AF:02:B6:2F:9D:07:8E:B8:D6:05:26:9F:4E:3C:5E:F3:EE:84:2B:34",
                            "authorityKeyIdentifier": "keyid:AC:89:58:64:1E:A8:6D:CC:3B:B9:38:4E:58:AE:A9:E7:CB:ED:DA:37\n",
                            "keyUsage": "Digital Signature, Key Encipherment",
                            "extendedKeyUsage": "TLS Web Server Authentication",
                            "crlDistributionPoints": "\nFull Name:\n  URI:http://crl.comodoca.com/COMODORSADomainValidationSecureServerCA.crl\n\nFull Name:\n  URI:http://crl.comodoca.com/COMODORSACertificationAuthority.crl\n\nFull Name:\n  URI:http://crl.pkioverheid.nl/RootLatestCRL-G2.crl\n\nFull Name:\n  URI:http://sr.symcb.com/sr.crl\n\nFull Name:\n  URI:http://crl.tcs.terena.org/TERENASSLCA.crl\n",
                            "subjectAltName": "DNS:*.google.nl, DNS:google.com, DNS:*.google.com, DNS:*.com, DNS:raymii.org, DNS:*.raymii.org",
                            "authorityInfoAccess": "CA Issuers - URI:http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt\nCA Issuers - URI:http://sr.symcb.com/sr.crt\nOCSP - URI:http://ocsp.comodoca.com\nOCSP - URI:http://ocsp.digidentity.eu/L4/services/ocsp\nOCSP - URI:http://sr.symcd.com\nOCSP - URI:http://ocsp.tcs.terena.org\n"
                        },
                        "purposes": {
                            "sslclient": {
                                "ca": "",
                                "general": ""
                            },
                            "sslserver": {
                                "ca": "",
                                "general": "1"
                            },
                            "nssslserver": {
                                "ca": "",
                                "general": "1"
                            },
                            "smimesign": {
                                "ca": "",
                                "general": ""
                            },
                            "smimeencrypt": {
                                "ca": "",
                                "general": ""
                            },
                            "crlsign": {
                                "ca": "",
                                "general": ""
                            },
                            "any": {
                                "ca": "1",
                                "general": "1"
                            },
                            "ocsphelper": {
                                "ca": "",
                                "general": "1"
                            },
                            "timestampsign": {
                                "ca": "",
                                "general": ""
                            }
                        }
                    },
                    "validation_type": "organisation",
                    "crl": {
                        "1": {
                            "crl_uri": "http://crl.comodoca.com/COMODORSADomainValidationSecureServerCA.crl",
                            "status": "ok",
                            "crl_last_update": "Mar 30 00:56:21 2015 GMT\n",
                            "crl_next_update": "Apr  3 00:56:21 2015 GMT\n"
                        },
                        "2": {
                            "crl_uri": "http://crl.comodoca.com/COMODORSACertificationAuthority.crl",
                            "status": "ok",
                            "crl_last_update": "Mar 29 19:04:22 2015 GMT\n",
                            "crl_next_update": "Apr  2 19:04:22 2015 GMT\n"
                        },
                        "3": {
                            "crl_uri": "http://crl.pkioverheid.nl/RootLatestCRL-G2.crl",
                            "status": "ok",
                            "crl_last_update": "Jan  8 10:19:45 2015 GMT\n",
                            "crl_next_update": "Jan  8 10:24:45 2016 GMT\n"
                        },
                        "4": {
                            "crl_uri": "http://sr.symcb.com/sr.crl",
                            "status": "ok",
                            "crl_last_update": "Mar 30 09:01:05 2015 GMT\n",
                            "crl_next_update": "Apr  6 09:01:05 2015 GMT\n"
                        },
                        "5": {
                            "crl_uri": "http://crl.tcs.terena.org/TERENASSLCA.crl",
                            "status": "ok",
                            "crl_last_update": "Mar 29 16:28:00 2015 GMT\n",
                            "crl_next_update": "Apr  2 16:28:00 2015 GMT\n"
                        }
                    },
                    "ocsp": "No OCSP URI found in certificate",
                    "hostname_in_san_or_cn": "n/a; ca signing certificate",
                    "serial": "3",
                    "key": {
                        "type": "rsa",
                        "bits": "4096",
                        "signature_algorithm": "sha1WithRSAEncryption",
                        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIK[...]Q7pn4iA==\n-----END CERTIFICATE-----\n",
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIC[...]UCAwEAAQ==\n-----END PUBLIC KEY-----\n",
                        "spki_hash": "MQEUI8vhXsSgP7y58AWpE3xfqepYOHILKdHRewQSWkE="
                    }
                }
            }
        }
    }


#### Hostname + Port

Params:

    - `host:ip` = Hostname:IP address
    - `port` = port to test (443, 993, 465, 8443 etc). 
    - ciphersuites = 1 to enumerate ciphersuites supported by the tested server. Takes longer. If not specified or not 1, ciphersuites will not be tested, used ciphersuite will be reported.


Port is optional and defaults to 443. Ciphersuites is optional and defaults to 0.

Example request:

    json.php?host=mijn.ing.nl&ciphersuites=1

Example response:

    {
        "data": {
            "connection": {
                "chain": {
                    "0": {
                        "name": "mijn.ing.nl",
                        "issuer": "Symantec Class 3 EV SSL CA - G3"
                    },
                    "1": {
                        "name": "Symantec Class 3 EV SSL CA - G3",
                        "issuer": "VeriSign Class 3 Public Primary Certification Authority - G5"
                    },
                    "validation": {
                        "status": "success"
                    }
                },
                "ip": "145.221.194.139",
                "hostname": "145.221.194.139",
                "port": "443",
                "protocols": {
                    "tlsv1.2": "1",
                    "tlsv1.1": "",
                    "tlsv1.0": "1",
                    "sslv3": ""
                },
                "supported_ciphersuites": [
                    "AES256-SHA256",
                    "AES256-SHA",
                    "AES128-SHA256",
                    "AES128-SHA",
                    "DES-CBC3-SHA"
                ],
                "tls_fallback_scsv": "unsupported",
                "strict_transport_security": "max-age=31622400",
                "public_key_pins": "not set",
                "ocsp_stapling": "not set",
                "openssl_version": "OpenSSL 1.0.2a 19 Mar 2015\n",
                "datetime_rfc2822": "Mon, 30 Mar 2015 12:18:11 +0200\n"
            },
            "chain": {
                "1": {
                    "cert_data": {
                        "name": "/jurisdictionC=NL/businessCategory=Private Organization/serialNumber=33031431/C=NL/postalCode=1102 MG/ST=Noord-Holland/L=Amsterdam Zuidoost/street=Bijlmerplein 888/O=ING BANK N.V./OU=Retail/CN=mijn.ing.nl",
                        "subject": {
                            "jurisdictionC": "NL",
                            "businessCategory": "Private Organization",
                            "serialNumber": "33031431",
                            "C": "NL",
                            "postalCode": "1102 MG",
                            "ST": "Noord-Holland",
                            "L": "Amsterdam Zuidoost",
                            "street": "Bijlmerplein 888",
                            "O": "ING BANK N.V.",
                            "OU": "Retail",
                            "CN": "mijn.ing.nl"
                        },
                        "hash": "0ede29ea",
                        "issuer": {
                            "C": "US",
                            "O": "Symantec Corporation",
                            "OU": "Symantec Trust Network",
                            "CN": "Symantec Class 3 EV SSL CA - G3"
                        },
                        "version": "2",
                        "serialNumber": "58839941462596964668433973121388685875",
                        "validFrom": "140918000000Z",
                        "validTo": "161029235959Z",
                        "validFrom_time_t": "1410998400",
                        "validTo_time_t": "1477785599",
                        "extensions": {
                            "subjectAltName": "DNS:mijn.ing.nl",
                            "basicConstraints": "CA:FALSE",
                            "keyUsage": "Digital Signature, Key Encipherment",
                            "extendedKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication",
                            "certificatePolicies": "Policy: 2.16.840.1.113733.1.7.23.6\n  CPS: https://d.symcb.com/cps\n  User Notice:\n    Explicit Text: https://d.symcb.com/rpa\n",
                            "authorityKeyIdentifier": "keyid:01:59:AB:E7:DD:3A:0B:59:A6:64:63:D6:CF:20:07:57:D5:91:E7:6A\n",
                            "crlDistributionPoints": "\nFull Name:\n  URI:http://sr.symcb.com/sr.crl\n",
                            "authorityInfoAccess": "OCSP - URI:http://sr.symcd.com\nCA Issuers - URI:http://sr.symcb.com/sr.crt\n"
                        },
                        "purposes": {
                            "sslclient": {
                                "ca": "",
                                "general": "1"
                            },
                            "sslserver": {
                                "ca": "",
                                "general": "1"
                            },
                            "nssslserver": {
                                "ca": "",
                                "general": "1"
                            },
                            "smimesign": {
                                "ca": "",
                                "general": ""
                            },
                            "smimeencrypt": {
                                "ca": "",
                                "general": ""
                            },
                            "crlsign": {
                                "ca": "",
                                "general": ""
                            },
                            "any": {
                                "ca": "1",
                                "general": "1"
                            },
                            "ocsphelper": {
                                "ca": "",
                                "general": "1"
                            },
                            "timestampsign": {
                                "ca": "",
                                "general": ""
                            }
                        }
                    },
                    "validation_type": "extended",
                    "crl": {
                        "1": {
                            "crl_uri": "http://sr.symcb.com/sr.crl",
                            "status": "ok",
                            "crl_last_update": "Mar 30 09:01:05 2015 GMT\n",
                            "crl_next_update": "Apr  6 09:01:05 2015 GMT\n"
                        }
                    },
                    "ocsp": {
                        "1": {
                            "status": "good",
                            "this_update": "Mar 27 09:39:42 2015 GMT",
                            "next_update": "Apr 3 09:39:42 2015 GMT",
                            "ocsp_uri": "http://sr.symcd.com"
                        }
                    },
                    "hostname_in_san_or_cn": "false",
                    "serial": "319",
                    "key": {
                        "type": "rsa",
                        "bits": "2048",
                        "signature_algorithm": "sha256WithRSAEncryption",
                        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMII[...]5rbdag==\n-----END CERTIFICATE-----\n",
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMII[...]DAQAB\n-----END PUBLIC KEY-----\n",
                        "spki_hash": "Y4ViGKugRm0tW3lflAY9ZGTj6xga6CtiZpMwzbCZARs="
                    }
                },
                "2": {
                    "cert_data": {
                        "name": "/C=US/O=Symantec Corporation/OU=Symantec Trust Network/CN=Symantec Class 3 EV SSL CA - G3",
                        "subject": {
                            "C": "US",
                            "O": "Symantec Corporation",
                            "OU": "Symantec Trust Network",
                            "CN": "Symantec Class 3 EV SSL CA - G3"
                        },
                        "hash": "a0f7ac3e",
                        "issuer": {
                            "C": "US",
                            "O": "VeriSign, Inc.",
                            "OU": [
                                "VeriSign Trust Network",
                                "(c) 2006 VeriSign, Inc. - For authorized use only"
                            ],
                            "CN": "VeriSign Class 3 Public Primary Certification Authority - G5"
                        },
                        "version": "2",
                        "serialNumber": "168652503989349361584430187274382793396",
                        "validFrom": "131031000000Z",
                        "validTo": "231030235959Z",
                        "validFrom_time_t": "1383177600",
                        "validTo_time_t": "1698710399",
                        "extensions": {
                            "authorityInfoAccess": "OCSP - URI:http://s2.symcb.com\n",
                            "basicConstraints": "CA:TRUE, pathlen:0",
                            "certificatePolicies": "Policy: X509v3 Any Policy\n  CPS: http://www.symauth.com/cps\n  User Notice:\n    Explicit Text: http://www.symauth.com/rpa\n",
                            "crlDistributionPoints": "\nFull Name:\n  URI:http://s1.symcb.com/pca3-g5.crl\n",
                            "keyUsage": "Certificate Sign, CRL Sign",
                            "subjectAltName": "DirName: CN = SymantecPKI-1-533",
                            "subjectKeyIdentifier": "01:59:AB:E7:DD:3A:0B:59:A6:64:63:D6:CF:20:07:57:D5:91:E7:6A",
                            "authorityKeyIdentifier": "keyid:7F:D3:65:A7:C2:DD:EC:BB:F0:30:09:F3:43:39:FA:02:AF:33:31:33\n"
                        },
                        "purposes": {
                            "sslclient": {
                                "ca": "1",
                                "general": ""
                            },
                            "sslserver": {
                                "ca": "1",
                                "general": ""
                            },
                            "nssslserver": {
                                "ca": "1",
                                "general": ""
                            },
                            "smimesign": {
                                "ca": "1",
                                "general": ""
                            },
                            "smimeencrypt": {
                                "ca": "1",
                                "general": ""
                            },
                            "crlsign": {
                                "ca": "1",
                                "general": "1"
                            },
                            "any": {
                                "ca": "1",
                                "general": "1"
                            },
                            "ocsphelper": {
                                "ca": "1",
                                "general": "1"
                            },
                            "timestampsign": {
                                "ca": "1",
                                "general": ""
                            }
                        }
                    },
                    "validation_type": "organisation",
                    "crl": {
                        "1": {
                            "crl_uri": "http://s1.symcb.com/pca3-g5.crl",
                            "status": "ok",
                            "crl_last_update": "Mar 18 00:00:00 2015 GMT\n",
                            "crl_next_update": "Jun 30 23:59:59 2015 GMT\n"
                        }
                    },
                    "ocsp": {
                        "1": {
                            "status": "good",
                            "this_update": "Mar 30 08:09:41 2015 GMT",
                            "next_update": "Apr 6 08:09:41 2015 GMT",
                            "ocsp_uri": "http://s2.symcb.com"
                        }
                    },
                    "hostname_in_san_or_cn": "n/a; ca signing certificate",
                    "serial": "105",
                    "key": {
                        "type": "rsa",
                        "bits": "2048",
                        "signature_algorithm": "sha256WithRSAEncryption",
                        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIF[...]tO7w+Q==\n-----END CERTIFICATE-----\n",
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMII[...]ww0\nDwIDAQAB\n-----END PUBLIC KEY-----\n",
                        "spki_hash": "gMxWOrX4PMQesK9qFNbYBxjBfjUvlkn/vN1n+L9lE5E="
                    }
                },
                "3": {
                    "cert_data": {
                        "name": "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5",
                        "subject": {
                            "C": "US",
                            "O": "VeriSign, Inc.",
                            "OU": [
                                "VeriSign Trust Network",
                                "(c) 2006 VeriSign, Inc. - For authorized use only"
                            ],
                            "CN": "VeriSign Class 3 Public Primary Certification Authority - G5"
                        },
                        "hash": "b204d74a",
                        "issuer": {
                            "C": "US",
                            "O": "VeriSign, Inc.",
                            "OU": "Class 3 Public Primary Certification Authority"
                        },
                        "version": "2",
                        "serialNumber": "49248466687453522052688216172288342269",
                        "validFrom": "061108000000Z",
                        "validTo": "211107235959Z",
                        "validFrom_time_t": "1162944000",
                        "validTo_time_t": "1636329599",
                        "extensions": {
                            "basicConstraints": "CA:TRUE",
                            "crlDistributionPoints": "\nFull Name:\n  URI:http://crl.verisign.com/pca3.crl\n",
                            "keyUsage": "Certificate Sign, CRL Sign",
                            "certificatePolicies": "Policy: X509v3 Any Policy\n  CPS: https://www.verisign.com/cps\n",
                            "subjectKeyIdentifier": "7F:D3:65:A7:C2:DD:EC:BB:F0:30:09:F3:43:39:FA:02:AF:33:31:33",
                            "1.3.6.1.5.5.7.1.12": "0_¡] [0Y0W0U\u0016\timage/gif0!0\u001f0\u0007\u0006\u0005+\u000e\u0003\u0002\u001a\u0004\u0014åÓ\u001a¬kÃÏjÔH\u0018,{\u0019.0%\u0016#http://logo.verisign.com/vslogo.gif",
                            "authorityInfoAccess": "OCSP - URI:http://ocsp.verisign.com\n",
                            "extendedKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication, Code Signing, Netscape Server Gated Crypto, 2.16.840.1.113733.1.8.1"
                        },
                        "purposes": {
                            "sslclient": {
                                "ca": "1",
                                "general": ""
                            },
                            "sslserver": {
                                "ca": "1",
                                "general": ""
                            },
                            "nssslserver": {
                                "ca": "1",
                                "general": ""
                            },
                            "smimesign": {
                                "ca": "",
                                "general": ""
                            },
                            "smimeencrypt": {
                                "ca": "",
                                "general": ""
                            },
                            "crlsign": {
                                "ca": "1",
                                "general": "1"
                            },
                            "any": {
                                "ca": "1",
                                "general": "1"
                            },
                            "ocsphelper": {
                                "ca": "1",
                                "general": "1"
                            },
                            "timestampsign": {
                                "ca": "1",
                                "general": ""
                            }
                        }
                    },
                    "validation_type": "organisation",
                    "crl": {
                        "1": {
                            "crl_uri": "http://crl.verisign.com/pca3.crl",
                            "status": "ok",
                            "crl_last_update": "Mar 18 00:00:00 2015 GMT\n",
                            "crl_next_update": "Jun 30 23:59:59 2015 GMT\n"
                        }
                    },
                    "ocsp": "No OCSP URI found in certificate",
                    "hostname_in_san_or_cn": "n/a; ca signing certificate",
                    "serial": "234",
                    "key": {
                        "type": "rsa",
                        "bits": "2048",
                        "signature_algorithm": "sha1WithRSAEncryption",
                        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIE0DCCB[...]JjhJ+xr3/\n-----END CERTIFICATE-----\n",
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMII[...]QAB\n-----END PUBLIC KEY-----\n",
                        "spki_hash": "JbQbUG5JMJUoI6brnx0x3vZF6jilxsapbXGVfjhN8Fg="
                    }
                }
            }
        }
    }
