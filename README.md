# SSL Decoder

Simple PHP script which decodes an SSL connection and/or certificate and displays information.

* Tries to give all the information you need instead of a rating. 
* Open source, so you can self host it. 
* Shows the entire certificate chain. 
* Allows to paste a CRL/Cert
* Validates the certificate, chain, CRL and OCSP (of every cert in the chain)
* Has easy copy-pastable PEM versions of certs
* Ciphersuite enumeration as an option.
* Fast.

### Features

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

### Requirements

- PHP 5.6+
- OpenSSL
- PHP must allow shell_exec and remote fopen.

### Installation

Unpack and go!

    cd /var/www
    git clone https://github.com/RaymiiOrg/ssl-decoder.git

Browse to https://your-server/ssl-decoder.

### Demo

See [https://tls.so](https://tls.so).

<a href="https://tls.so"><img src="http://i.imgur.com/R1BQlLVm.png" /></a>

### License

GNU Affero GPL v3: [https://www.gnu.org/licenses/agpl-3.0.html](https://www.gnu.org/licenses/agpl-3.0.html)
