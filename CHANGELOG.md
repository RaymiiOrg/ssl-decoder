# Changelog

## 1.5

- Fix bug in CSR page rendering

- Add result page saving
- Add AJAX form loader

## 1.4

- Fix bug where HSTS and HPKP would not work if host was IP
- Fix bug where downloaded CRL file would be empty
- Fix bug where hostname verification would fail if SAN has "othername:<unsupported>"

- Add OCSP stapling support

- Improve OCSP validation result parsing
- Improve CRL validation error message