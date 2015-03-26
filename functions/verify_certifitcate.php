<?php
// Copyright (C) 2015 Remy van Elst

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

function verify_certificate_hostname($raw_cert, $host, $port) {
    $cert_data = openssl_x509_parse($raw_cert);
    if ($cert_data['subject']['CN']) {
        $cert_host_names = [];
        $cert_host_names[] = $cert_data['subject']['CN'];
        if ($cert_data['extensions']['subjectAltName']) {
            foreach ( explode("DNS:", $cert_data['extensions']['subjectAltName']) as $altName ) {
                foreach (explode(",", $altName) as $key => $value) {
                    if ( !empty(str_replace(',', "", "$value"))) {
                        $cert_host_names[] = str_replace(" ", "", str_replace(',', "", "$value"));
                    }
                }
            }
        }
        foreach ($cert_host_names as $key => $hostname) {
            if (strpos($hostname, "*.") === 0) {
// wildcard hostname from cert
                if (explode(".", $host, 2)[1] == explode(".", $hostname, 2)[1] ) {
// split cert name and host name on . and compare everything after the first dot
                    return true;
                }
            }
// no wildcard, just regular match
            if ($host == $hostname) {
                return true;
            }
        }
// no match
        return false;
    }
}



function verify_cert_issuer_by_subject_hash($raw_cert_data, $raw_next_cert_data) {
  global $random_blurp;
  $tmp_dir = "/tmp/";
  openssl_x509_export_to_file($raw_next_cert_data, $tmp_dir.$random_blurp.'.cert_issuer.pem');
  openssl_x509_export_to_file($raw_cert_data, $tmp_dir.$random_blurp.'.cert_client.pem'); 

//echo htmlspecialchars('openssl ocsp -no_nonce -CAfile '.$root_ca.' -issuer '.$tmp_dir.$random_blurp.'.cert_issuer.pem -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri).'" 2>&1');

  $cert_issuer_hash = shell_exec('openssl x509 -noout -issuer_hash -in '.$tmp_dir.$random_blurp.'.cert_client.pem 2>&1');
  $issuer_subject_hash = shell_exec('openssl x509 -noout -subject_hash -in '.$tmp_dir.$random_blurp.'.cert_issuer.pem 2>&1');

  unlink($tmp_dir.$random_blurp.'.cert_client.pem');
  unlink($tmp_dir.$random_blurp.'.cert_issuer.pem');
  if ( $cert_issuer_hash == $issuer_subject_hash ) {
    return true;
  } else {
    return false;
  }
}

function cert_signature_algorithm($raw_cert_data) {
  $cert_read = openssl_x509_read($raw_cert_data);
  openssl_x509_export($cert_read, $out, FALSE);
  $signature_algorithm = null;
  if(preg_match('/^\s+Signature Algorithm:\s*(.*)\s*$/m', $out, $match)) $signature_algorithm = $match[1];
  return($signature_algorithm);
}

function spki_hash($raw_cert_data) {
    global $random_blurp;
    $tmp_dir = '/tmp/'; 
    openssl_x509_export_to_file($raw_cert_data, $tmp_dir.$random_blurp.'.cert_client.pem'); 
    $output = shell_exec('openssl x509 -noout -in '.$tmp_dir.$random_blurp.'.cert_client.pem  -pubkey | openssl asn1parse -noout -inform pem -out '.$tmp_dir.$random_blurp.'.public.key; openssl dgst -sha256 -binary '. $tmp_dir . $random_blurp . '.public.key | openssl enc -base64 2>&1');

    unlink($tmp_dir.$random_blurp.'.cert_client.pem');
    unlink($tmp_dir.$random_blurp.'.public.key');
    return(trim(htmlspecialchars($output)));
}

?>