# SSL Decoder

PHP script which decodes an SSL connection and/or certificate and displays information.

* Tries to give all the information you need instead of a rating. 
* Open source, so you can self host it. 
* Shows the entire certificate chain. 
* Allows to paste a CRL/Cert.
* Allows a custom port (smtps, imaps, https, 8080, 8443, etc).
* Validates the certificate, chain, CRL and OCSP (of every cert in the chain).
* Has easy copy-pastable PEM versions of certs.
* Constructs correct CA Chain if wrong chain is found.
* DNSSEC checks
* Ciphersuite enumeration.
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
- Constructs correct CA Chain if wrong chain is found.
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
- Certificate Transparency submission
- DNSSEC check
- Certificate Hash calculation

## Requirements

- PHP 5.6+
- OpenSSL
- PHP must allow shell_exec and remote fopen.
- PHP modules: `php-intl`, `php-bcmath`, `php-curl`, `php-mbstring`, `php-xml`.

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

See [https://ssldecoder.org](https://ssldecoder.org).

<a href="https://ssldecoder.org"><img src="http://i.imgur.com/R1BQlLVm.png" /></a>

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
                        "signatureTypeSN": "RSA-SHA1",
                        "signatureTypeLN": "sha1WithRSAEncryption",
                        "signatureTypeNID": "65",
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
                    "cert_issued_in_future": "",
                    "cert_expired": "",
                    "cert_expires_in_less_than_thirty_days": "",
                    "validation_type": "organization",
                    "crl": {
                        "1": {
                            "crl_uri": "http://crl.comodoca.com/COMODORSADomainValidationSecureServerCA.crl",
                            "status": "ok",
                            "crl_last_update": "Oct 17 03:05:20 2015 GMT\n",
                            "crl_next_update": "Oct 21 03:05:20 2015 GMT\n"
                        },
                        "2": {
                            "crl_uri": "http://crl.comodoca.com/COMODORSACertificationAuthority.crl",
                            "status": "ok",
                            "crl_last_update": "Oct 16 22:36:24 2015 GMT\n",
                            "crl_next_update": "Oct 20 22:36:24 2015 GMT\n"
                        },
                        "3": {
                            "crl_uri": "http://crl.pkioverheid.nl/RootLatestCRL-G2.crl",
                            "status": "ok",
                            "crl_last_update": "Oct  7 08:07:08 2015 GMT\n",
                            "crl_next_update": "Oct  6 08:07:08 2016 GMT\n"
                        },
                        "4": {
                            "crl_uri": "http://sr.symcb.com/sr.crl",
                            "status": "ok",
                            "crl_last_update": "Oct 17 09:01:05 2015 GMT\n",
                            "crl_next_update": "Oct 24 09:01:05 2015 GMT\n"
                        },
                        "5": {
                            "crl_uri": "http://crl.tcs.terena.org/TERENASSLCA.crl",
                            "status": "ok",
                            "crl_last_update": "Oct 16 19:51:43 2015 GMT\n",
                            "crl_next_update": "Oct 20 19:51:43 2015 GMT\n"
                        }
                    },
                    "ocsp": "No issuer cert provided. Unable to send OCSP request.",
                    "hostname_in_san_or_cn": "n/a; ca signing certificate",
                    "serialNumber": "3",
                    "hash": {
                        "md5": "6b6d56a47b77e7359d4f8c70b1f111ed",
                        "sha1": "cec626a06d433e62dd58ff93c2b20276db94e94b",
                        "sha256": "d4293bf8b3e4adad6d5ffecff2df35b7cf70da1ae5ded60093d018b67ed3cd5b",
                        "sha384": "e63a3a581bafe44204d64270d28ec0a778ab7ebc4f8abed6f155e3f3915bf3f757e0511988fd5af5828fd39edd6382b7",
                        "sha512": "74241f5f1d6783988125d358eb2486ff72e6ec61efb1adce77058861a6da190eb4f03edcc4b7e0814c0a8b3763a38e8133c2d2be354b8c97febc224fcf30b355"
                    },
                    "key": {
                        "type": "rsa",
                        "bits": "4096",
                        "signature_algorithm": "sha1WithRSAEncryption",
                        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIKmDCCBoCgAwIBAgIBAzANBgkqhkiG9w0BAQUFADCBgjELMAkGA1UEBhMCTkwx\nFTATBgNVBAgMDFp1aWQgSG9sbGFuZDESMBAGA1UEBwwJUm90dGVyZGFtMRowGAYD\nVQQKDBFTcGFya2xpbmcgTmV0d29yazEVMBMGA1UECwwMU3BhcmtsaW5nIENBMRUw\nEwYDVQQDDAxTcGFya2xpbmcgQ0EwHhcNMTUwMzI5MTExMzU4WhcNMTcwMzI4MTEx\nMzU4WjBvMRMwEQYDVQQDDApnb29nbGUuY29tMRIwEAYDVQQIDAlSb3R0ZXJkYW0x\nCzAJBgNVBAYTAk5MMRowGAYDVQQKDBFTcGFya2xpbmcgTmV0d29yazEbMBkGA1UE\nCwwSU3BhcmtsaW5nIFdlYnNpdGVzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\nCgKCAgEAoi3dJz7UcdbIU+fM5S44tk8MM++PguUDVnC2wviFgpg6Q+INGnAofUoe\ny+CtiqNWZyey0QO9AglEX8Q0z3eTSTf29ntBgfMUwpMkkXuXDrdH78/zh83L4VkO\nr+87cRZi4clskcIE1DJrw/bN9oyRAjWdKZfpaMtLT9ab4yWNOCqy0gzxiG7NfAfv\nvqxF6Rwg9lNVJmRqwxP54qa2ayjmqVPhBgLqpRRfE2CPxxiCb8KdYhbFVaEraXKM\nRMFans+XSD6I5e0N3BTjAf2+v6Dzjyt9sQFh/EpjqZrTe2JCwg3C44hy8RdohuN+\nt0OsvAO46Xk7cP8Z/hqxSpcvNRhcjFQ6bCv74OXInVu5pSHydARSlM0FKfhAjaVl\ncu9Q/pkQ2rhFtvpKnJr+3tZiSlRpuK0MLDLMhgWopfMzXvBAzSxDC0hXODzjHA0M\noTbW4vDmAv6bn+JXzxHsaxjkbpr1x2FRbwj8ZuwIzUIZP46iRVzZ97p+6D9LK40q\nhI50eiuFQfigqXoe5BrniQtkZi293H4dKJzvoLSAbjYB0PLD6I7zkNt8QtVDLhSz\n5u7fC890VYK9DZZP1B8RAYn91SRRFBBnJDSRgvutA/RSkXkLXviCw4oDIfijTrg4\nW35ASS5LjAOwbucKY3lsbd2lbLGcyxro9Z9aeLxZEX49X3u1dhUCAwEAAaOCAykw\nggMlMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK8Cti+dB4641gUmn048XvPu\nhCs0MB8GA1UdIwQYMBaAFKyJWGQeqG3MO7k4TliuqefL7do3MAsGA1UdDwQEAwIF\noDATBgNVHSUEDDAKBggrBgEFBQcDATCCASQGA1UdHwSCARswggEXMEmgR6BFhkNo\ndHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9SU0FEb21haW5WYWxpZGF0aW9u\nU2VjdXJlU2VydmVyQ0EuY3JsMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNv\nbS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDA0oDKgMIYuaHR0\ncDovL2NybC5wa2lvdmVyaGVpZC5ubC9Sb290TGF0ZXN0Q1JMLUcyLmNybDAgoB6g\nHIYaaHR0cDovL3NyLnN5bWNiLmNvbS9zci5jcmwwL6AtoCuGKWh0dHA6Ly9jcmwu\ndGNzLnRlcmVuYS5vcmcvVEVSRU5BU1NMQ0EuY3JsMFEGA1UdEQRKMEiCCyouZ29v\nZ2xlLm5sggpnb29nbGUuY29tggwqLmdvb2dsZS5jb22CBSouY29tggpyYXltaWku\nb3JnggwqLnJheW1paS5vcmcwggEzBggrBgEFBQcBAQSCASUwggEhME8GCCsGAQUF\nBzAChkNodHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9DT01PRE9SU0FEb21haW5WYWxp\nZGF0aW9uU2VjdXJlU2VydmVyQ0EuY3J0MCYGCCsGAQUFBzAChhpodHRwOi8vc3Iu\nc3ltY2IuY29tL3NyLmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2Rv\nY2EuY29tMDcGCCsGAQUFBzABhitodHRwOi8vb2NzcC5kaWdpZGVudGl0eS5ldS9M\nNC9zZXJ2aWNlcy9vY3NwMB8GCCsGAQUFBzABhhNodHRwOi8vc3Iuc3ltY2QuY29t\nMCYGCCsGAQUFBzABhhpodHRwOi8vb2NzcC50Y3MudGVyZW5hLm9yZzANBgkqhkiG\n9w0BAQUFAAOCBAEAWM5iu/7PUCJyhN3nR77FxCWanLeAIWU8NJEpspjZgjH5j0Oc\n8mqYmJEzfrIg4O/9ZoqrUV1OiDW7fyf7DHW9yTwmcc/wute05TRN3dtUXmzNMk6B\nBfaBbwuXjL8ZEZcZnHKSvWxMmqG2Rx3csA68I53qluedP2b61dQiTwiBa1SH4v3G\n78ZeJi03RSoB6Fbn6l+cIfPNI877d+pzOvBs05Vj57bdb+7Ji0lzDWQNV7uuc3/R\nWVEfZv0ErBgVxlI3EautBQaGZCf1ltwyo2n8wTkVou6wFIX5K4LkWOYuSiu/cgB3\n+Ol21TGZf+oqhMCkmYp313MSbu8HUO7COpJI0B4IZ4Zm+YelKGjhDX8bx5l4TrGh\nfbsuoHpesRx3/zEnoP4VGAkuN7H5PALhF3G/RI8jKwBdLA3ANhochqsICmvu9Li2\nSJAxT87/h4azUYGvd9ZnEWl5rMSqZkFtZhw0y/PVKgw0rXuaVfvqqSuETeq6gGp1\nLYtJUq4LO4Yvg7QXxa1qCeZmTbea+QmE+Wsi0jPYQ3LkLkOpDh9nsuY3Ru7f+gIB\ndELs2TTpOKcg7eKLEpv8JGLXv0NYwc1aqKyL6jycjeGCC9riw8Xla3ZLgAx4IJyM\nJV7qRUxg4jMK+pQd5q1Z3RX5PIwPdzFkHdBnPH6k7GCOqEzQnmR8Hql9xUwi5svM\niitX4Y7FbXW1zxzaBX6SLCfE60lUhSh7ik+b9TK77Gg/uLDmdanXpFguSezGCHZ2\njL4mYLeXWV88WVXEH4tmXsCQrQsmnlcTAJpvXW7NvV8lCjqh3RbXXG7RHd2IEWfr\nZAAaT+nwNIW/x8mXJxUx9RpCKVS+Cm8Q/jDHT9X7DxdHlzzzvN+rv8yy6P/p8HGP\nY84H84qVP9uQgoAxArKRIVIO7ZjaT38V5tlidTxjyf38y0E/HV+LM2vjl3wsefQw\nU8dzNGCNvEWycVrBrZArjITkHFMq/3VUODlX4M3GTZ4XuZR+EGB0kF3uyApE/fLX\nP4qzfsTw/0p0Xn7K/f3HsYyyXbh17sR761gbQCXHJN1YE0F5U4F7DESgbhWZrLJ6\ntCG5Np/mrQ7rKIJxKqSdSKicKYgi0lSk0bq9eF0QLDvECiCiEDT33D8ju+KjPXie\nd6bddv3wUguPUOg7hYr1DLaRwZ9FtfM2UqYtEQxwuebDragUY2gO0tT2wtqNFhwl\nXnPFJhWi3Atz/cjvdlktvhhaqHJLUkmaXVsgys470rUUq+JETCUVM8dKYfC3Nir1\nPcl+ic8lyHLRserIynKLsnYlCgMb6DdbyMXWUUe2OGuUvz9OI09VjY8vAnKfM0E0\nQ3aqS6U2xoswso+ov1HkVOOlcNFpJAqQ7pn4iA==\n-----END CERTIFICATE-----\n",
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoi3dJz7UcdbIU+fM5S44\ntk8MM++PguUDVnC2wviFgpg6Q+INGnAofUoey+CtiqNWZyey0QO9AglEX8Q0z3eT\nSTf29ntBgfMUwpMkkXuXDrdH78/zh83L4VkOr+87cRZi4clskcIE1DJrw/bN9oyR\nAjWdKZfpaMtLT9ab4yWNOCqy0gzxiG7NfAfvvqxF6Rwg9lNVJmRqwxP54qa2ayjm\nqVPhBgLqpRRfE2CPxxiCb8KdYhbFVaEraXKMRMFans+XSD6I5e0N3BTjAf2+v6Dz\njyt9sQFh/EpjqZrTe2JCwg3C44hy8RdohuN+t0OsvAO46Xk7cP8Z/hqxSpcvNRhc\njFQ6bCv74OXInVu5pSHydARSlM0FKfhAjaVlcu9Q/pkQ2rhFtvpKnJr+3tZiSlRp\nuK0MLDLMhgWopfMzXvBAzSxDC0hXODzjHA0MoTbW4vDmAv6bn+JXzxHsaxjkbpr1\nx2FRbwj8ZuwIzUIZP46iRVzZ97p+6D9LK40qhI50eiuFQfigqXoe5BrniQtkZi29\n3H4dKJzvoLSAbjYB0PLD6I7zkNt8QtVDLhSz5u7fC890VYK9DZZP1B8RAYn91SRR\nFBBnJDSRgvutA/RSkXkLXviCw4oDIfijTrg4W35ASS5LjAOwbucKY3lsbd2lbLGc\nyxro9Z9aeLxZEX49X3u1dhUCAwEAAQ==\n-----END PUBLIC KEY-----\n",
                        "spki_hash": "MQEUI8vhXsSgP7y58AWpE3xfqepYOHILKdHRewQSWkE="
                    },
                    "warning": [
                        "SHA-1 certificate. Upgrade (re-issue) to SHA-256 or better."
                    ]
                }
            }
        },
        "version": "2.9"
    }


#### Hostname + Port

Params:

    - `host:ip` = Hostname:IP address (both required)
    - `port` = port to test (443, 993, 465, 8443 etc). 
    - `fastcheck` = 1 for fast check, anything else for regular check. Limited connection data enumeration, no certificate transparency submission. Only applicable when host:ip is used.


Port is optional and defaults to 443. Fastcheck is optional and defaults to 0.

Example fast request:

    json.php?host=xs4all.nl:194.109.6.93&port=443&fastcheck=1

Example fast response:

    {
        "data": {
            "connection": {
                "checked_hostname": "xs4all.nl",
                "chain": [
                    {
                        "name": "*.xs4all.nl",
                        "issuer": "GlobalSign Domain Validation CA - SHA256 - G2"
                    },
                    {
                        "name": "GlobalSign Domain Validation CA - SHA256 - G2",
                        "issuer": "GlobalSign Root CA"
                    }
                ],
                "validation": {
                    "status": "success"
                },
                "ip": "194.109.6.93",
                "hostname": "xs4all.nl",
                "port": "443",
                "openssl_version": "OpenSSL 1.0.1e-fips 11 Feb 2013\n",
                "datetime_rfc2822": "Sat, 17 Oct 2015 17:34:10 +0200\n"
            },
            "chain": {
                "1": {
                    "cert_data": {
                        "name": "/C=NL/OU=Domain Control Validated/CN=*.xs4all.nl",
                        "subject": {
                            "C": "NL",
                            "OU": "Domain Control Validated",
                            "CN": "*.xs4all.nl"
                        },
                        "hash": "1b6ff7eb",
                        "issuer": {
                            "C": "BE",
                            "O": "GlobalSign nv-sa",
                            "CN": "GlobalSign Domain Validation CA - SHA256 - G2"
                        },
                        "version": "2",
                        "serialNumber": "1492413605911531362906337146940506873397418",
                        "validFrom": "141128145702Z",
                        "validTo": "170707133301Z",
                        "validFrom_time_t": "1417186622",
                        "validTo_time_t": "1499434381",
                        "signatureTypeSN": "RSA-SHA256",
                        "signatureTypeLN": "sha256WithRSAEncryption",
                        "signatureTypeNID": "668",
                        "extensions": {
                            "keyUsage": "Digital Signature, Key Encipherment",
                            "certificatePolicies": "Policy: 2.23.140.1.2.1\n  CPS: https://www.globalsign.com/repository/\n",
                            "subjectAltName": "DNS:*.xs4all.nl, DNS:xs4all.nl",
                            "basicConstraints": "CA:FALSE",
                            "extendedKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication",
                            "crlDistributionPoints": "\nFull Name:\n  URI:http://crl.globalsign.com/gs/gsdomainvalsha2g2.crl\n",
                            "authorityInfoAccess": "CA Issuers - URI:http://secure.globalsign.com/cacert/gsdomainvalsha2g2r1.crt\nOCSP - URI:http://ocsp2.globalsign.com/gsdomainvalsha2g2\n",
                            "subjectKeyIdentifier": "80:38:0D:6B:57:B3:D5:98:E9:10:29:8E:5E:70:5C:B0:D2:CF:9E:93",
                            "authorityKeyIdentifier": "keyid:EA:4E:7C:D4:80:2D:E5:15:81:86:26:8C:82:6D:C0:98:A4:CF:97:0F\n"
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
                    "cert_issued_in_future": "",
                    "cert_expired": "",
                    "cert_expires_in_less_than_thirty_days": "",
                    "validation_type": "domain",
                    "issuer_valid": "1",
                    "crl": {
                        "1": {
                            "crl_uri": "http://crl.globalsign.com/gs/gsdomainvalsha2g2.crl",
                            "status": "ok",
                            "crl_last_update": "Oct 16 23:00:00 2015 GMT\n",
                            "crl_next_update": "Oct 23 23:00:00 2015 GMT\n"
                        }
                    },
                    "ocsp": {
                        "1": {
                            "status": "good",
                            "this_update": "Oct 17 12:11:04 2015 GMT",
                            "next_update": "Oct 18 00:11:04 2015 GMT",
                            "ocsp_uri": "http://ocsp2.globalsign.com/gsdomainvalsha2g2"
                        }
                    },
                    "hostname_checked": "xs4all.nl",
                    "hostname_in_san_or_cn": "true",
                    "serialNumber": "11:21:CF:35:4D:B8:66:6D:0C:BD:89:2D:DA:C8:AA:32:00:AA",
                    "hash": {
                        "md5": "f727346b711a0147b083a2499ef6fa6c",
                        "sha1": "4b8372cc8fe4bd48732e226d58dfb3aed1117b97",
                        "sha256": "223a6659d06e9a81390938659e9ef241579e82b820d6afd8e17d548aedea3f13",
                        "sha384": "746f62592a7204b26c584547dfff943b79efb862ab8f9fd748261e2d70838caf8c8b73ce7aa07ec85958419fd2670ccc",
                        "sha512": "790edcc263f90fd8c43d0bafc4bdb7f36f0609795bf0bb0c1e4cdc68bf3e716b389e58a914d4cbc91d277fd77dd5f2e2cea057dbee6b8fc0bc2e8cf27d2aa6e5"
                    },
                    "tlsa": {
                        "tlsa_hash": "223a6659d06e9a81390938659e9ef241579e82b820d6afd8e17d548aedea3f13",
                        "tlsa_usage": "1",
                        "tlsa_selector": "0",
                        "tlsa_matching_type": "1",
                        "error": "none"
                    },
                    "key": {
                        "type": "rsa",
                        "bits": "3072",
                        "signature_algorithm": "sha256WithRSAEncryption",
                        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIFfDCCBGSgAwIBAgISESHPNU24Zm0MvYkt2siqMgCqMA0GCSqGSIb3DQEBCwUA\nMGAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTYwNAYD\nVQQDEy1HbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gU0hBMjU2IC0g\nRzIwHhcNMTQxMTI4MTQ1NzAyWhcNMTcwNzA3MTMzMzAxWjBGMQswCQYDVQQGEwJO\nTDEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRQwEgYDVQQDDAsq\nLnhzNGFsbC5ubDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKeQ1ChO\nYwwmNtUCYtVOjBs0fYyFXxsgdvcYlCrUzwkStH5s/aOGKnH/VnR/6UJRGVHHyBYY\nAfxLLYOlnWNoe4NJBQw9BI0FOlbi7d99iVGSgmJVEYwbFspnpJ6NoIUY+yVMnV51\npPYPPHOxQX0xs6GnGpY+XE7TUueqqHuicFtgAe/7OUWo8sNgNE6JMewM5Y5JsRhh\nELTj938x6EeYybR+PZq5f5YS423ElGGn27w+8VK8/hcWQyoB8bgjRrory5GaaWg0\nKCF/9WC9vUbqhfMLzCy4YmfrHSrensKksrxP4/QbhsMTgTZ8FdNlNmi+f6ZMiD3l\n56vGuyaDLONNzCgY3wylI/561SNFtJmc7zMHp6B7Zlqug6rGPZbRfYJaGHYuYLhx\nKba1YWGOy6KBNuS4DfRDElUyuT1F7Jij1q2qcn40OBrVTDIyAnbMFAjyzRLBaFeR\nea8ykdevLPRO/Wnu6fp8d77SR4jEI2i3wFwm83sK/hqIO9ILq03+/d7T1wIDAQAB\no4IByDCCAcQwDgYDVR0PAQH/BAQDAgWgMEkGA1UdIARCMEAwPgYGZ4EMAQIBMDQw\nMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRv\ncnkvMCEGA1UdEQQaMBiCCyoueHM0YWxsLm5sggl4czRhbGwubmwwCQYDVR0TBAIw\nADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwQwYDVR0fBDwwOjA4oDag\nNIYyaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9ncy9nc2RvbWFpbnZhbHNoYTJn\nMi5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMEcGCCsGAQUFBzAChjtodHRwOi8vc2Vj\ndXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc2RvbWFpbnZhbHNoYTJnMnIxLmNy\ndDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL2dzZG9t\nYWludmFsc2hhMmcyMB0GA1UdDgQWBBSAOA1rV7PVmOkQKY5ecFyw0s+ekzAfBgNV\nHSMEGDAWgBTqTnzUgC3lFYGGJoyCbcCYpM+XDzANBgkqhkiG9w0BAQsFAAOCAQEA\nFZZXPetKakrpMsZQGvr4W8ozBaZjx1HAjXDplq3q5u7fan4D7K5l++amy5GgYy4K\nETtpHm1KCXg15fysdZfzsL5TBu9IfpMNLMcMUqDZ+BBdJf3ajObYWMfA1IM45ekb\nMgaYZkX62hSuJADfAPwtIHohqAGJ8qH1WRpdakCEezgNx/reTUGpepZT3AWxDfJ9\n68P9dmIV30EUnrscJ22g8K53Pl47YYCEtBdrIw9KvX4Pi0x/ff+aN8lA+gFg9/8T\nulKeDQBOk1PHedes/HxugDxUEEqgSq7/sEoMGceywkczgvIi3vPuK1ClpwmBUjSs\nsLMOjC48NYY10+xsfcddbA==\n-----END CERTIFICATE-----\n",
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp5DUKE5jDCY21QJi1U6M\nGzR9jIVfGyB29xiUKtTPCRK0fmz9o4Yqcf9WdH/pQlEZUcfIFhgB/Estg6WdY2h7\ng0kFDD0EjQU6VuLt332JUZKCYlURjBsWymekno2ghRj7JUydXnWk9g88c7FBfTGz\noacalj5cTtNS56qoe6JwW2AB7/s5Rajyw2A0Tokx7AzljkmxGGEQtOP3fzHoR5jJ\ntH49mrl/lhLjbcSUYafbvD7xUrz+FxZDKgHxuCNGuivLkZppaDQoIX/1YL29RuqF\n8wvMLLhiZ+sdKt6ewqSyvE/j9BuGwxOBNnwV02U2aL5/pkyIPeXnq8a7JoMs403M\nKBjfDKUj/nrVI0W0mZzvMwenoHtmWq6DqsY9ltF9gloYdi5guHEptrVhYY7LooE2\n5LgN9EMSVTK5PUXsmKPWrapyfjQ4GtVMMjICdswUCPLNEsFoV5F5rzKR168s9E79\nae7p+nx3vtJHiMQjaLfAXCbzewr+Gog70gurTf793tPXAgMBAAE=\n-----END PUBLIC KEY-----\n",
                        "spki_hash": "AjyEDlnyvgr9VisPwMkyfWzhfSlGRgPNBcMzFeXIVJc="
                    }
                },
                "2": {
                    "cert_data": {
                        "name": "/C=BE/O=GlobalSign nv-sa/CN=GlobalSign Domain Validation CA - SHA256 - G2",
                        "subject": {
                            "C": "BE",
                            "O": "GlobalSign nv-sa",
                            "CN": "GlobalSign Domain Validation CA - SHA256 - G2"
                        },
                        "hash": "d7d634d4",
                        "issuer": {
                            "C": "BE",
                            "O": "GlobalSign nv-sa",
                            "OU": "Root CA",
                            "CN": "GlobalSign Root CA"
                        },
                        "version": "2",
                        "serialNumber": "4835703278459909592596000",
                        "validFrom": "140220100000Z",
                        "validTo": "240220100000Z",
                        "validFrom_time_t": "1392890400",
                        "validTo_time_t": "1708423200",
                        "signatureTypeSN": "RSA-SHA256",
                        "signatureTypeLN": "sha256WithRSAEncryption",
                        "signatureTypeNID": "668",
                        "extensions": {
                            "keyUsage": "Certificate Sign, CRL Sign",
                            "basicConstraints": "CA:TRUE, pathlen:0",
                            "subjectKeyIdentifier": "EA:4E:7C:D4:80:2D:E5:15:81:86:26:8C:82:6D:C0:98:A4:CF:97:0F",
                            "certificatePolicies": "Policy: X509v3 Any Policy\n  CPS: https://www.globalsign.com/repository/\n",
                            "crlDistributionPoints": "\nFull Name:\n  URI:http://crl.globalsign.net/root.crl\n",
                            "authorityInfoAccess": "OCSP - URI:http://ocsp.globalsign.com/rootr1\n",
                            "authorityKeyIdentifier": "keyid:60:7B:66:1A:45:0D:97:CA:89:50:2F:7D:04:CD:34:A8:FF:FC:FD:4B\n"
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
                    "cert_issued_in_future": "",
                    "cert_expired": "",
                    "cert_expires_in_less_than_thirty_days": "",
                    "validation_type": "organization",
                    "crl": {
                        "1": {
                            "crl_uri": "http://crl.globalsign.net/root.crl",
                            "status": "ok",
                            "crl_last_update": "Oct  7 00:00:00 2015 GMT\n",
                            "crl_next_update": "Jan 15 00:00:00 2016 GMT\n"
                        }
                    },
                    "ocsp": "No issuer cert provided. Unable to send OCSP request.",
                    "hostname_in_san_or_cn": "n/a; ca signing certificate",
                    "serialNumber": "40:00:00:00:00:14:44:EF:03:E2:0",
                    "hash": {
                        "md5": "ecf535c505b7752b0af188a915a23786",
                        "sha1": "736a4dc679d682da321563647c60f699f0dfc268",
                        "sha256": "bfdf4cf3f143ad0db912d8ab3a7c12f617b9ea60ce8b1f4e44f74270fb21b19b",
                        "sha384": "ad0a47cb5aacce9fb4549b4d586dd552cb5201192cfad8997eaab2ef4d9d489b432cecbf3a57f70d6c725aefdc265053",
                        "sha512": "0418e33fed6724155d2a6c702f99e2e8c9b0b7fd163d9b5c7afce9f01cb151242ae7a0111dbafee1948c5e05b928106c639ac0f3663abea2abcea83b2e3c1a0d"
                    },
                    "key": {
                        "type": "rsa",
                        "bits": "2048",
                        "signature_algorithm": "sha256WithRSAEncryption",
                        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIEYzCCA0ugAwIBAgILBAAAAAABRE7wPiAwDQYJKoZIhvcNAQELBQAwVzELMAkG\nA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\nb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xNDAyMjAxMDAw\nMDBaFw0yNDAyMjAxMDAwMDBaMGAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\nYWxTaWduIG52LXNhMTYwNAYDVQQDEy1HbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0\naW9uIENBIC0gU0hBMjU2IC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQCp3cwOs+IyOd1JIqgTaZOHiOEM7nF9vZCHll1Z8syz0lhXV/lG72wm2DZC\njn4wsy+aPlN7H262okxFHzzTFZMcie089Ffeyr3sBppqKqAZUn9R0XQ5CJ+r69eG\nExWXrjbDVGYOWvKgc4Ux47JkFGr/paKOJLu9hVIVonnu8LXuPbj0fYC82ZA1ZbgX\nqa2zmJ+gfn1u+z+tfMIbWTaW2jcyS0tdNQJjjtunz2LuzC7Ujcm9PGqRcqIip3It\nINH6yjfaGJjmFiRxJUvE5XuJUgkC/VkrBG7KB4HUs9ra2+PMgKhWBwZ8lgg3nds4\ntmI0kWIHdAE42HIw4uuQcSZiwFfzAgMBAAGjggElMIIBITAOBgNVHQ8BAf8EBAMC\nAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU6k581IAt5RWBhiaMgm3A\nmKTPlw8wRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8v\nd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMDMGA1UdHwQsMCowKKAmoCSG\nImh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5uZXQvcm9vdC5jcmwwPQYIKwYBBQUHAQEE\nMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9yb290\ncjEwHwYDVR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswDQYJKoZIhvcNAQEL\nBQADggEBANdFnqDc4ONhWgt9d4QXLWVagpqNoycqhffJ7+mG/dRHzQFSlsVDvTex\n4bjyqdKKEYRxkRWJ3AKdC8tsM4U0KJ4gsrGX3G0LEME8zV/qXdeYMcU0mVwAYVXE\nGwJbxeOJyLS4bx448lYm6UHvPc2smU9ZSlctS32ux4j71pg79eXw6ImJuYsDy1oj\nH6T9uOr7Lp2uanMJvPzVoLVEgqtEkS5QLlfBQ9iRBIvpES5ftD953x77PzAAi1Pj\ntywdO02L3ORkHQRYM68bVeerDL8wBHTk8w4vMDmNSwSMHnVmZkngvkA0x1xaUZK6\nEjxS1QSCVS1npd+3lXzuP8MIugS+wEY=\n-----END CERTIFICATE-----\n",
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqd3MDrPiMjndSSKoE2mT\nh4jhDO5xfb2Qh5ZdWfLMs9JYV1f5Ru9sJtg2Qo5+MLMvmj5Tex9utqJMRR880xWT\nHIntPPRX3sq97AaaaiqgGVJ/UdF0OQifq+vXhhMVl642w1RmDlryoHOFMeOyZBRq\n/6WijiS7vYVSFaJ57vC17j249H2AvNmQNWW4F6mts5ifoH59bvs/rXzCG1k2lto3\nMktLXTUCY47bp89i7swu1I3JvTxqkXKiIqdyLSDR+so32hiY5hYkcSVLxOV7iVIJ\nAv1ZKwRuygeB1LPa2tvjzICoVgcGfJYIN53bOLZiNJFiB3QBONhyMOLrkHEmYsBX\n8wIDAQAB\n-----END PUBLIC KEY-----\n",
                        "spki_hash": "PL1/TTDEe9Cm2lb2X0tixyQC7zaPREm/V0IHJscTCmw="
                    }
                }
            },
            "certificate_transparency": []
        },
        "version": "2.9"
    }

Example regular request:

    json.php?host=xs4all.nl:194.109.6.93&port=443

Example regular response:

    {
        "data": {
            "connection": {
                "checked_hostname": "xs4all.nl",
                "chain": [
                    {
                        "name": "*.xs4all.nl",
                        "issuer": "GlobalSign Domain Validation CA - SHA256 - G2"
                    },
                    {
                        "name": "GlobalSign Domain Validation CA - SHA256 - G2",
                        "issuer": "GlobalSign Root CA"
                    }
                ],
                "validation": {
                    "status": "success"
                },
                "ip": "194.109.6.93",
                "hostname": "xs4all.nl",
                "port": "443",
                "heartbleed": "not_vulnerable",
                "compression": "",
                "protocols": {
                    "tlsv1.2": "1",
                    "tlsv1.1": "1",
                    "tlsv1.0": "1",
                    "sslv3": "",
                    "sslv2": ""
                },
                "used_ciphersuite": {
                    "name": "ECDHE-RSA-AES256-GCM-SHA384",
                    "bits": "256"
                },
                "tls_fallback_scsv": "supported",
                "strict_transport_security": "not set",
                "warning": [
                    "HTTP Strict Transport Security not set.",
                    "OCSP Stapling not enabled."
                ],
                "public_key_pins": "not set",
                "ocsp_stapling": "not set",
                "heartbeat": "1",
                "openssl_version": "OpenSSL 1.0.1e-fips 11 Feb 2013\n",
                "datetime_rfc2822": "Sat, 17 Oct 2015 17:34:58 +0200\n"
            },
            "chain": {
                "1": {
                    "cert_data": {
                        "name": "/C=NL/OU=Domain Control Validated/CN=*.xs4all.nl",
                        "subject": {
                            "C": "NL",
                            "OU": "Domain Control Validated",
                            "CN": "*.xs4all.nl"
                        },
                        "hash": "1b6ff7eb",
                        "issuer": {
                            "C": "BE",
                            "O": "GlobalSign nv-sa",
                            "CN": "GlobalSign Domain Validation CA - SHA256 - G2"
                        },
                        "version": "2",
                        "serialNumber": "1492413605911531362906337146940506873397418",
                        "validFrom": "141128145702Z",
                        "validTo": "170707133301Z",
                        "validFrom_time_t": "1417186622",
                        "validTo_time_t": "1499434381",
                        "signatureTypeSN": "RSA-SHA256",
                        "signatureTypeLN": "sha256WithRSAEncryption",
                        "signatureTypeNID": "668",
                        "extensions": {
                            "keyUsage": "Digital Signature, Key Encipherment",
                            "certificatePolicies": "Policy: 2.23.140.1.2.1\n  CPS: https://www.globalsign.com/repository/\n",
                            "subjectAltName": "DNS:*.xs4all.nl, DNS:xs4all.nl",
                            "basicConstraints": "CA:FALSE",
                            "extendedKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication",
                            "crlDistributionPoints": "\nFull Name:\n  URI:http://crl.globalsign.com/gs/gsdomainvalsha2g2.crl\n",
                            "authorityInfoAccess": "CA Issuers - URI:http://secure.globalsign.com/cacert/gsdomainvalsha2g2r1.crt\nOCSP - URI:http://ocsp2.globalsign.com/gsdomainvalsha2g2\n",
                            "subjectKeyIdentifier": "80:38:0D:6B:57:B3:D5:98:E9:10:29:8E:5E:70:5C:B0:D2:CF:9E:93",
                            "authorityKeyIdentifier": "keyid:EA:4E:7C:D4:80:2D:E5:15:81:86:26:8C:82:6D:C0:98:A4:CF:97:0F\n"
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
                    "cert_issued_in_future": "",
                    "cert_expired": "",
                    "cert_expires_in_less_than_thirty_days": "",
                    "validation_type": "domain",
                    "issuer_valid": "1",
                    "crl": {
                        "1": {
                            "crl_uri": "http://crl.globalsign.com/gs/gsdomainvalsha2g2.crl",
                            "status": "ok",
                            "crl_last_update": "Oct 16 23:00:00 2015 GMT\n",
                            "crl_next_update": "Oct 23 23:00:00 2015 GMT\n"
                        }
                    },
                    "ocsp": {
                        "1": {
                            "status": "good",
                            "this_update": "Oct 17 12:11:04 2015 GMT",
                            "next_update": "Oct 18 00:11:04 2015 GMT",
                            "ocsp_uri": "http://ocsp2.globalsign.com/gsdomainvalsha2g2"
                        }
                    },
                    "hostname_checked": "xs4all.nl",
                    "hostname_in_san_or_cn": "true",
                    "serialNumber": "11:21:CF:35:4D:B8:66:6D:0C:BD:89:2D:DA:C8:AA:32:00:AA",
                    "hash": {
                        "md5": "f727346b711a0147b083a2499ef6fa6c",
                        "sha1": "4b8372cc8fe4bd48732e226d58dfb3aed1117b97",
                        "sha256": "223a6659d06e9a81390938659e9ef241579e82b820d6afd8e17d548aedea3f13",
                        "sha384": "746f62592a7204b26c584547dfff943b79efb862ab8f9fd748261e2d70838caf8c8b73ce7aa07ec85958419fd2670ccc",
                        "sha512": "790edcc263f90fd8c43d0bafc4bdb7f36f0609795bf0bb0c1e4cdc68bf3e716b389e58a914d4cbc91d277fd77dd5f2e2cea057dbee6b8fc0bc2e8cf27d2aa6e5"
                    },
                    "tlsa": {
                        "tlsa_hash": "223a6659d06e9a81390938659e9ef241579e82b820d6afd8e17d548aedea3f13",
                        "tlsa_usage": "1",
                        "tlsa_selector": "0",
                        "tlsa_matching_type": "1",
                        "error": "none"
                    },
                    "key": {
                        "type": "rsa",
                        "bits": "3072",
                        "signature_algorithm": "sha256WithRSAEncryption",
                        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIFfDCCBGSgAwIBAgISESHPNU24Zm0MvYkt2siqMgCqMA0GCSqGSIb3DQEBCwUA\nMGAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTYwNAYD\nVQQDEy1HbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gU0hBMjU2IC0g\nRzIwHhcNMTQxMTI4MTQ1NzAyWhcNMTcwNzA3MTMzMzAxWjBGMQswCQYDVQQGEwJO\nTDEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRQwEgYDVQQDDAsq\nLnhzNGFsbC5ubDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKeQ1ChO\nYwwmNtUCYtVOjBs0fYyFXxsgdvcYlCrUzwkStH5s/aOGKnH/VnR/6UJRGVHHyBYY\nAfxLLYOlnWNoe4NJBQw9BI0FOlbi7d99iVGSgmJVEYwbFspnpJ6NoIUY+yVMnV51\npPYPPHOxQX0xs6GnGpY+XE7TUueqqHuicFtgAe/7OUWo8sNgNE6JMewM5Y5JsRhh\nELTj938x6EeYybR+PZq5f5YS423ElGGn27w+8VK8/hcWQyoB8bgjRrory5GaaWg0\nKCF/9WC9vUbqhfMLzCy4YmfrHSrensKksrxP4/QbhsMTgTZ8FdNlNmi+f6ZMiD3l\n56vGuyaDLONNzCgY3wylI/561SNFtJmc7zMHp6B7Zlqug6rGPZbRfYJaGHYuYLhx\nKba1YWGOy6KBNuS4DfRDElUyuT1F7Jij1q2qcn40OBrVTDIyAnbMFAjyzRLBaFeR\nea8ykdevLPRO/Wnu6fp8d77SR4jEI2i3wFwm83sK/hqIO9ILq03+/d7T1wIDAQAB\no4IByDCCAcQwDgYDVR0PAQH/BAQDAgWgMEkGA1UdIARCMEAwPgYGZ4EMAQIBMDQw\nMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRv\ncnkvMCEGA1UdEQQaMBiCCyoueHM0YWxsLm5sggl4czRhbGwubmwwCQYDVR0TBAIw\nADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwQwYDVR0fBDwwOjA4oDag\nNIYyaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9ncy9nc2RvbWFpbnZhbHNoYTJn\nMi5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMEcGCCsGAQUFBzAChjtodHRwOi8vc2Vj\ndXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc2RvbWFpbnZhbHNoYTJnMnIxLmNy\ndDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL2dzZG9t\nYWludmFsc2hhMmcyMB0GA1UdDgQWBBSAOA1rV7PVmOkQKY5ecFyw0s+ekzAfBgNV\nHSMEGDAWgBTqTnzUgC3lFYGGJoyCbcCYpM+XDzANBgkqhkiG9w0BAQsFAAOCAQEA\nFZZXPetKakrpMsZQGvr4W8ozBaZjx1HAjXDplq3q5u7fan4D7K5l++amy5GgYy4K\nETtpHm1KCXg15fysdZfzsL5TBu9IfpMNLMcMUqDZ+BBdJf3ajObYWMfA1IM45ekb\nMgaYZkX62hSuJADfAPwtIHohqAGJ8qH1WRpdakCEezgNx/reTUGpepZT3AWxDfJ9\n68P9dmIV30EUnrscJ22g8K53Pl47YYCEtBdrIw9KvX4Pi0x/ff+aN8lA+gFg9/8T\nulKeDQBOk1PHedes/HxugDxUEEqgSq7/sEoMGceywkczgvIi3vPuK1ClpwmBUjSs\nsLMOjC48NYY10+xsfcddbA==\n-----END CERTIFICATE-----\n",
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp5DUKE5jDCY21QJi1U6M\nGzR9jIVfGyB29xiUKtTPCRK0fmz9o4Yqcf9WdH/pQlEZUcfIFhgB/Estg6WdY2h7\ng0kFDD0EjQU6VuLt332JUZKCYlURjBsWymekno2ghRj7JUydXnWk9g88c7FBfTGz\noacalj5cTtNS56qoe6JwW2AB7/s5Rajyw2A0Tokx7AzljkmxGGEQtOP3fzHoR5jJ\ntH49mrl/lhLjbcSUYafbvD7xUrz+FxZDKgHxuCNGuivLkZppaDQoIX/1YL29RuqF\n8wvMLLhiZ+sdKt6ewqSyvE/j9BuGwxOBNnwV02U2aL5/pkyIPeXnq8a7JoMs403M\nKBjfDKUj/nrVI0W0mZzvMwenoHtmWq6DqsY9ltF9gloYdi5guHEptrVhYY7LooE2\n5LgN9EMSVTK5PUXsmKPWrapyfjQ4GtVMMjICdswUCPLNEsFoV5F5rzKR168s9E79\nae7p+nx3vtJHiMQjaLfAXCbzewr+Gog70gurTf793tPXAgMBAAE=\n-----END PUBLIC KEY-----\n",
                        "spki_hash": "AjyEDlnyvgr9VisPwMkyfWzhfSlGRgPNBcMzFeXIVJc="
                    }
                },
                "2": {
                    "cert_data": {
                        "name": "/C=BE/O=GlobalSign nv-sa/CN=GlobalSign Domain Validation CA - SHA256 - G2",
                        "subject": {
                            "C": "BE",
                            "O": "GlobalSign nv-sa",
                            "CN": "GlobalSign Domain Validation CA - SHA256 - G2"
                        },
                        "hash": "d7d634d4",
                        "issuer": {
                            "C": "BE",
                            "O": "GlobalSign nv-sa",
                            "OU": "Root CA",
                            "CN": "GlobalSign Root CA"
                        },
                        "version": "2",
                        "serialNumber": "4835703278459909592596000",
                        "validFrom": "140220100000Z",
                        "validTo": "240220100000Z",
                        "validFrom_time_t": "1392890400",
                        "validTo_time_t": "1708423200",
                        "signatureTypeSN": "RSA-SHA256",
                        "signatureTypeLN": "sha256WithRSAEncryption",
                        "signatureTypeNID": "668",
                        "extensions": {
                            "keyUsage": "Certificate Sign, CRL Sign",
                            "basicConstraints": "CA:TRUE, pathlen:0",
                            "subjectKeyIdentifier": "EA:4E:7C:D4:80:2D:E5:15:81:86:26:8C:82:6D:C0:98:A4:CF:97:0F",
                            "certificatePolicies": "Policy: X509v3 Any Policy\n  CPS: https://www.globalsign.com/repository/\n",
                            "crlDistributionPoints": "\nFull Name:\n  URI:http://crl.globalsign.net/root.crl\n",
                            "authorityInfoAccess": "OCSP - URI:http://ocsp.globalsign.com/rootr1\n",
                            "authorityKeyIdentifier": "keyid:60:7B:66:1A:45:0D:97:CA:89:50:2F:7D:04:CD:34:A8:FF:FC:FD:4B\n"
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
                    "cert_issued_in_future": "",
                    "cert_expired": "",
                    "cert_expires_in_less_than_thirty_days": "",
                    "validation_type": "organization",
                    "crl": {
                        "1": {
                            "crl_uri": "http://crl.globalsign.net/root.crl",
                            "status": "ok",
                            "crl_last_update": "Oct  7 00:00:00 2015 GMT\n",
                            "crl_next_update": "Jan 15 00:00:00 2016 GMT\n"
                        }
                    },
                    "ocsp": "No issuer cert provided. Unable to send OCSP request.",
                    "hostname_in_san_or_cn": "n/a; ca signing certificate",
                    "serialNumber": "40:00:00:00:00:14:44:EF:03:E2:0",
                    "hash": {
                        "md5": "ecf535c505b7752b0af188a915a23786",
                        "sha1": "736a4dc679d682da321563647c60f699f0dfc268",
                        "sha256": "bfdf4cf3f143ad0db912d8ab3a7c12f617b9ea60ce8b1f4e44f74270fb21b19b",
                        "sha384": "ad0a47cb5aacce9fb4549b4d586dd552cb5201192cfad8997eaab2ef4d9d489b432cecbf3a57f70d6c725aefdc265053",
                        "sha512": "0418e33fed6724155d2a6c702f99e2e8c9b0b7fd163d9b5c7afce9f01cb151242ae7a0111dbafee1948c5e05b928106c639ac0f3663abea2abcea83b2e3c1a0d"
                    },
                    "key": {
                        "type": "rsa",
                        "bits": "2048",
                        "signature_algorithm": "sha256WithRSAEncryption",
                        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIEYzCCA0ugAwIBAgILBAAAAAABRE7wPiAwDQYJKoZIhvcNAQELBQAwVzELMAkG\nA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\nb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xNDAyMjAxMDAw\nMDBaFw0yNDAyMjAxMDAwMDBaMGAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\nYWxTaWduIG52LXNhMTYwNAYDVQQDEy1HbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0\naW9uIENBIC0gU0hBMjU2IC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQCp3cwOs+IyOd1JIqgTaZOHiOEM7nF9vZCHll1Z8syz0lhXV/lG72wm2DZC\njn4wsy+aPlN7H262okxFHzzTFZMcie089Ffeyr3sBppqKqAZUn9R0XQ5CJ+r69eG\nExWXrjbDVGYOWvKgc4Ux47JkFGr/paKOJLu9hVIVonnu8LXuPbj0fYC82ZA1ZbgX\nqa2zmJ+gfn1u+z+tfMIbWTaW2jcyS0tdNQJjjtunz2LuzC7Ujcm9PGqRcqIip3It\nINH6yjfaGJjmFiRxJUvE5XuJUgkC/VkrBG7KB4HUs9ra2+PMgKhWBwZ8lgg3nds4\ntmI0kWIHdAE42HIw4uuQcSZiwFfzAgMBAAGjggElMIIBITAOBgNVHQ8BAf8EBAMC\nAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU6k581IAt5RWBhiaMgm3A\nmKTPlw8wRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8v\nd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMDMGA1UdHwQsMCowKKAmoCSG\nImh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5uZXQvcm9vdC5jcmwwPQYIKwYBBQUHAQEE\nMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9yb290\ncjEwHwYDVR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswDQYJKoZIhvcNAQEL\nBQADggEBANdFnqDc4ONhWgt9d4QXLWVagpqNoycqhffJ7+mG/dRHzQFSlsVDvTex\n4bjyqdKKEYRxkRWJ3AKdC8tsM4U0KJ4gsrGX3G0LEME8zV/qXdeYMcU0mVwAYVXE\nGwJbxeOJyLS4bx448lYm6UHvPc2smU9ZSlctS32ux4j71pg79eXw6ImJuYsDy1oj\nH6T9uOr7Lp2uanMJvPzVoLVEgqtEkS5QLlfBQ9iRBIvpES5ftD953x77PzAAi1Pj\ntywdO02L3ORkHQRYM68bVeerDL8wBHTk8w4vMDmNSwSMHnVmZkngvkA0x1xaUZK6\nEjxS1QSCVS1npd+3lXzuP8MIugS+wEY=\n-----END CERTIFICATE-----\n",
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqd3MDrPiMjndSSKoE2mT\nh4jhDO5xfb2Qh5ZdWfLMs9JYV1f5Ru9sJtg2Qo5+MLMvmj5Tex9utqJMRR880xWT\nHIntPPRX3sq97AaaaiqgGVJ/UdF0OQifq+vXhhMVl642w1RmDlryoHOFMeOyZBRq\n/6WijiS7vYVSFaJ57vC17j249H2AvNmQNWW4F6mts5ifoH59bvs/rXzCG1k2lto3\nMktLXTUCY47bp89i7swu1I3JvTxqkXKiIqdyLSDR+so32hiY5hYkcSVLxOV7iVIJ\nAv1ZKwRuygeB1LPa2tvjzICoVgcGfJYIN53bOLZiNJFiB3QBONhyMOLrkHEmYsBX\n8wIDAQAB\n-----END PUBLIC KEY-----\n",
                        "spki_hash": "PL1/TTDEe9Cm2lb2X0tixyQC7zaPREm/V0IHJscTCmw="
                    }
                }
            },
            "certificate_transparency": {
                "https://ct.ws.symantec.com": {
                    "error_message": "Root certificate is not trusted.",
                    "success": ""
                },
                "https://ct.googleapis.com/pilot": {
                    "sct_version": "0",
                    "id": "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=",
                    "timestamp": "1417969515094",
                    "extensions": "",
                    "signature": "BAMARzBFAiEAlhYyYtcLnWz4V5QiaVlmGFuTAxzF4zJ1k86UUBL66jQCIFobWJkRKhwJMdRK76qNGpcsvHKgTyB0vABoKkgbDi/z"
                },
                "https://ct.googleapis.com/aviator": {
                    "sct_version": "0",
                    "id": "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=",
                    "timestamp": "1417983849982",
                    "extensions": "",
                    "signature": "BAMARzBFAiBHbD9Lk3v2PSRLWnNxbOgQ6Hr6wPu8iQvhuF+uvHfdGAIhAOqIbuRYl160Vb0fKy/a4PEmS4pif5Chxm05Y2SNNiNk"
                },
                "https://ct.googleapis.com/rocketeer": {
                    "sct_version": "0",
                    "id": "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=",
                    "timestamp": "1418006457229",
                    "extensions": "",
                    "signature": "BAMARjBEAiAoPi1qugNgCyhrOLQ9pM1I3JjqipZpQN5EQdMPnPQO+wIgAc/56CEaTEHZiEAqbLSy8s2bIG/izHjLhtJmFou7vPc="
                },
                "https://ct1.digicert-ct.com/log": {
                    "sct_version": "0",
                    "id": "VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=",
                    "timestamp": "1443089839391",
                    "extensions": "",
                    "signature": "BAMARzBFAiEA1SP2iUkCyj6Zk3TvvLD0vjiAjMXB1sMeABzeQAYqjQcCIC57eYUFwMHDCaNuFKtJhpXSwF7+BTIJIP6oS+OuyGCC"
                },
                "https://ct.izenpe.com": {
                    "error_message": "could not verify certificate chain",
                    "success": ""
                },
                "https://ctlog.api.venafi.com": {
                    "sct_version": "0",
                    "id": "rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=",
                    "timestamp": "1443089840283",
                    "extensions": "",
                    "signature": "BAEBAE+SeC3on+3HB5MH5ynSJF0q0xLGLy+mpMRsWClGT/1p3a4Bek3XSVuMNye6pSmg8m3gKmb0UTDbSVp37dNWfWbEdAD+aX1BsU538ZW1QVsssountJdcEO0ECUpfu6ZvvVyHRZvqo3rwQG3xcF4BZIu3XSa3g8jUgdOFloGWSpCLYmG1ngOGD7w9ch/zvobCM84Q6u6NadH1g/CQL84xAzu167nnbaPnMPF2bI2n1gEV3IdmSPu51zuMce1a1EwbSAYlTenI00zSVUpM66LgesluvRn90+XqI1oLZpqwqY21eaAQXefCd3RwFPaL77aVN+azdhvnrk9/1qQGF9iJyy4="
                },
                "https://log.certly.io": {
                    "sct_version": "0",
                    "id": "zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA=",
                    "timestamp": "1443089852702",
                    "extensions": "",
                    "signature": "BAMASDBGAiEAoy6MEGaNGNB2xCuRI8+c6opl+osD9M6czjFodbLKSBUCIQCgaZws1gzcwpisy6z0lUpEFjfznkbBjCsGd4TdJJl7vg=="
                }
            }
        },
        "version": "2.9"
    }