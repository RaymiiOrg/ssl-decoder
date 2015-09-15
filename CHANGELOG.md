# Changelog

## 2.7

- Add debian weak keys check.
- Add Lets Encrypt Signing certs: https://letsencrypt.org/2015/06/04/isrg-ca-certs.html
- Check heartbeat extension.
- Set title based on check.
- Reset warning count in menu correctly.
- Remove spaces from json variable names.

## 2.6

- Fix testing of IPv6 only hosts.
- Fix correct reverse DNS lookup for IPv6.
- Don't test OCSP stapling, TLS_FALLBACK_SCSV and SSL Compression on IPv6 hosts because of bugs in OpenSSL's tools (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest). Don't give invalid test results, instead, give user a warning about it.
- Add host header to get_headers function (fix #35).

## 2.5

- Show specific endpoint picker when multiple A/AAAA records exist.
- Add support for testing specific IP's with specific hostnames (instead of what DNS says)

## 2.4

- Add SSL Compressio check
- Add Heartbleed test (requires python2)
- Add some tooltips for topics

## 2.3

- Add warning if certificate expires in < 30 days.

## 2.2

- Add SSLv2 test
- Fix long duration and possible timeout on non-http(s) tests

## 2.1

- Add json API endpoint (see README).
- Rewrote internals to use same endpoint.
- Add warnings for connection and certificate issues.
- Don't follow redirects during HTTP header gathering.

## 2.0

- Add TLS_FALLBACK_SCSV check.
- Lower some timeouts from 5 to 2.

## 1.9

- Add navigation menu
- Add green color if HSTS/HPKP headers are available.
- Partial fix to make IDN's work instead of fail.
- Fix issue with OCSP validation and HTTP 1.1 (StartCOM)
- Fix CRL validation issue for self signed CRL URI's
- Fix http header case sensitive validation (HSTS, HPKP)
- Fix OCSP status display
- Relicense under Affero GPL

## 1.8

- Add certificate chain validation.
- Make some chiphersuites red.

## 1.7

- Split code up in seperate files
- Add SPKI hash

## 1.6

- Remove JSON output
- Add ciphersuite enumeration

## 1.5

- Fix bug in CSR page rendering
- Fix a few PHP warnings by better checking input parameters

- Add PEM display of cert and pubkey
- Add result page saving
- Add AJAX form loader

## 1.4

- Fix bug where HSTS and HPKP would not work if host was IP
- Fix bug where downloaded CRL file would be empty
- Fix bug where hostname verification would fail if SAN has "othername:<unsupported>"

- Add OCSP stapling support

- Improve OCSP validation result parsing
- Improve CRL validation error message
