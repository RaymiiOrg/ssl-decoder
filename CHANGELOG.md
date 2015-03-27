# Changelog

## 1.9

- Add navigation menu
- Fix issue with OCSP validation and HTTP 1.1 (StartCOM)
- Fix CRL validation issue for self signed CRL URI's
- Fix http header case sensitive validation (HSTS, HPKP)
- Add green color if HSTS/HPKP headers are available.
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
