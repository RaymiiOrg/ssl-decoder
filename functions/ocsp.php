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

function ocsp_stapling($host, $ip, $port) {
  global $timeout;
  if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
    return false;
  }
  $result = "";
  $output = shell_exec('echo | timeout ' . $timeout . ' openssl s_client -servername "' . escapeshellcmd($host) . '" -connect "' . escapeshellcmd($ip) . ':' . escapeshellcmd($port) . '" -tlsextdebug -status 2>&1 | sed -n "/OCSP response:/,/---/p"'); 
  if (strpos($output, "no response sent") !== false) { 
    $result = array("working" => 0,
      "cert_status" => "No response sent");
  }
  if (strpos($output, "OCSP Response Data:") !== false) {
    $lines = array();
    $output = preg_replace("/[[:blank:]]+/"," ", $output);
    $stapling_status_lines = explode("\n", $output);
    $stapling_status_lines = array_map('trim', $stapling_status_lines);
    foreach($stapling_status_lines as $line) {
      if(endsWith($line, ":") == false) {
        list($k, $v) = explode(":", $line);
        $lines[trim($k)] = trim($v);
      }
    }
    $result = array("working" => 1,
      "cert_status" => $lines["Cert Status"],
      "this_update" => $lines["This Update"],
      "next_update" => $lines["Next Update"],
      "responder_id" => $lines["Responder Id"],
      "hash_algorithm" => $lines["Hash Algorithm"],
      "signature_algorithm" => $lines["Signature Algorithm"],
      "issuer_name_hash" => $lines["Issuer Name Hash"]);
  }
  return $result;
}

function ocsp_verify_json($raw_cert_data, $raw_next_cert_data, $ocsp_uri) {
  global $random_blurp, $timeout;
  $result = array();
  $tmp_dir = '/tmp/'; 
  $root_ca = getcwd() . '/cacert.pem';
  $pem_issuer = "";
  $pem_client = "";
  openssl_x509_export($raw_cert_data, $pem_client);
  openssl_x509_export_to_file($raw_cert_data, $tmp_dir.$random_blurp.'.cert_client.pem'); 
  openssl_x509_export($raw_next_cert_data, $pem_issuer);
  openssl_x509_export_to_file($raw_next_cert_data, $tmp_dir.$random_blurp.'.cert_issuer.pem');
  $isser_loc = $tmp_dir.$random_blurp.'.cert_issuer.pem';

  // Some OCSP's want HTTP/1.1 but OpenSSL does not do that. Add Host header as workaround.
  $ocsp_host = parse_url($ocsp_uri, PHP_URL_HOST);

  //pre_dump('openssl ocsp -no_nonce -CAfile '.$root_ca.' -issuer '.$isser_loc.' -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri) . '" -header "HOST" "'. escapeshellcmd($ocsp_host) . '" 2>&1');

  $output = shell_exec('timeout ' . $timeout . ' | openssl ocsp -no_nonce -CAfile '.$root_ca.' -issuer '.$isser_loc .' -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri) . '" -header "HOST" "'. escapeshellcmd($ocsp_host) . '" 2>&1');
  
  $filter_output = shell_exec('timeout ' . $timeout . ' | openssl ocsp -no_nonce -CAfile '.$root_ca.' -issuer '.$isser_loc .' -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri) . '" -header "HOST" "'. escapeshellcmd($ocsp_host) . '" 2>&1 | grep -v -e "to get local issuer certificate" -e "signer certificate not found" -e "Response Verify" -e "'. $tmp_dir.$random_blurp.'.cert_client.pem"');

  $output = preg_replace("/[[:blank:]]+/"," ", $output);
  $ocsp_status_lines = explode("\n", $output);
  $ocsp_status_lines = array_map('trim', $ocsp_status_lines);
  foreach($ocsp_status_lines as $line) {
    if(endsWith($line, ":") == false) {
      list($k, $v) = explode(":", $line, 2);
      if (trim($k)) {
        $lines[trim($k)] = trim($v); 
      }
    }
  }  
  
  if ($lines[$tmp_dir . $random_blurp . ".cert_client.pem"] == "good") { 
    $result["status"] = "good";
  } else if ($lines[$tmp_dir . $random_blurp . ".cert_client.pem"] == "revoked") {
    $result["status"] = "revoked";
  } else {
    $result["error"] = $filter_output;
    $result["status"] = "unknown";
  }  

  if (isset($lines["This Update"])) {
    $result["this_update"] = $lines["This Update"];
  }
  if (isset($lines["Next Update"])) {
    $result["next_update"] = $lines["Next Update"];
  }
  if (isset($lines["Reason"])) {
    $result["reason"] = $lines["Reason"];
  }
  if (isset($lines["Revocation Time"])) {
    $result["revocation_time"] = $lines["Revocation Time"];
  }
  $result["ocsp_uri"] = $ocsp_uri;
  
  unlink($tmp_dir.$random_blurp.'.cert_client.pem');
  unlink($tmp_dir.$random_blurp.'.cert_issuer.pem');

  return $result;
}

?>