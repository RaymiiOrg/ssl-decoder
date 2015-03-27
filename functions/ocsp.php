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

function ocsp_stapling($host, $port){
    $result = "";
    $output = shell_exec('echo | timeout 5 openssl s_client -connect "' . escapeshellcmd($host) . ':' . escapeshellcmd($port) . '" -tlsextdebug -status 2>&1 | sed -n "/OCSP response:/,/---/p"'); 
    if (strpos($output, "no response sent") !== false) { 
        $result = array("working" => 0,
            "cert_status" => "No response sent");
        return;
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
            "Cert Status" => $lines["Cert Status"],
            "This Update" => $lines["This Update"],
            "Next Update" => $lines["Next Update"],
            "Responder ID" => $lines["Responder Id"],
            "Hash Algorithm" => $lines["Hash Algorithm"],
            "Signature Algorithm" => $lines["Signature Algorithm"],
            "Issuer Name Hash" => $lines["Issuer Name Hash"]);
    }
    return $result;
}

function ocsp_verify($raw_cert_data, $raw_next_cert_data) {
    global $random_blurp;
    $cert_data = openssl_x509_parse($raw_cert_data);
    $tmp_dir = '/tmp/'; 
    $root_ca = getcwd() . '/cacert.pem';

    $pem_issuer = "";
    $pem_client = "";
    $ocsp_uri = explode("OCSP - URI:", $cert_data['extensions']['authorityInfoAccess'])[1];
    $ocsp_uri = explode("\n", $ocsp_uri)[0];
    $ocsp_uri = explode(" ", $ocsp_uri)[0];
    if (empty($ocsp_uri) ) {
        $result = array('unknown' => "Could not find OCSP URI", );
        return $result;
    }
    openssl_x509_export($raw_cert_data, $pem_client);
    openssl_x509_export($raw_next_cert_data, $pem_issuer);
    openssl_x509_export_to_file($raw_next_cert_data, $tmp_dir.$random_blurp.'.cert_issuer.pem');
    openssl_x509_export_to_file($raw_cert_data, $tmp_dir.$random_blurp.'.cert_client.pem'); 

    // Some OCSP's want HTTP/1.1 but OpenSSL does not do that. Add Host header as workaround.
    $ocsp_host = parse_url($ocsp_uri, PHP_URL_HOST);

    //echo '<pre>' . htmlspecialchars('openssl ocsp -no_nonce -CAfile '.$root_ca.' -issuer '.$tmp_dir.$random_blurp.'.cert_issuer.pem -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri) . '" -header "HOST" "'. escapeshellcmd($ocsp_host) . '" 2>&1') . '</pre>';

    $output = shell_exec('openssl ocsp -no_nonce -CAfile '.$root_ca.' -issuer '.$tmp_dir.$random_blurp.'.cert_issuer.pem -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri) . '" -header "HOST" "'. escapeshellcmd($ocsp_host) . '" 2>&1');
    $filter_output = shell_exec('openssl ocsp -no_nonce -CAfile '.$root_ca.' -issuer '.$tmp_dir.$random_blurp.'.cert_issuer.pem -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri) . '" -header "HOST" "'. escapeshellcmd($ocsp_host) . '" 2>&1 | grep -v -e "to get local issuer certificate" -e "signer certificate not found" -e "Response Verify" -e "'. $tmp_dir.$random_blurp.'.cert_client.pem"');



    $lines = array();
    $output = preg_replace("/[[:blank:]]+/"," ", $output);
    $ocsp_status_lines = explode("\n", $output);
    $ocsp_status_lines = array_map('trim', $ocsp_status_lines);
    foreach($ocsp_status_lines as $line) {
        if(endsWith($line, ":") == false) {
            list($k, $v) = explode(":", $line, 2);
            $lines[trim($k)] = trim($v);
        }
    }  

    $result = array("This Update" => $lines["This Update"],
        "Next Update" => $lines["Next Update"],
        "Reason" => $lines["Reason"],
        "Revocation Time" => $lines["Revocation Time"],
        "ocsp_verify_status" => $lines[$tmp_dir . $random_blurp . ".cert_client.pem"]);
    if ($result["ocsp_verify_status"] == "good") { 
        $result["good"] = $filter_output;
    } else if ($result["ocsp_verify_status"] == "revoked") {
        $result["revoked"] = $filter_output;
    } else {
        $result["unknown"] = $filter_output;
    }
    unlink($tmp_dir.$random_blurp.'.cert_client.pem');
    unlink($tmp_dir.$random_blurp.'.cert_issuer.pem');
    return $result;
}

?>