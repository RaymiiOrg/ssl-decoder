<!--
    Copyright (C) 2014 Remy van Elst

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->
<!doctype html>
<html lang="en">
<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SSL Decoder</title>
  <link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css">
  <script src="//ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js"></script> 
  <script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.0/js/bootstrap.min.js"></script>
  <link rel="stylesheet" href="ssl.css">
</head>
<body>
  <a id="top-of-page"></a>
  <div class="container-fluid ">
    <div class="row"><div class="col-md-10 col-md-offset-1">
      <div class="page-header" >
        <h1>SSL Decoder</h1>
      </div>


      <?php
      $random_blurp = rand(1000,99999);


# 2014-11-10 (nov) from wikipedia
      $ev_oids = array("1.3.6.1.4.1.34697.2.1", "1.3.6.1.4.1.34697.2.2", "1.3.6.1.4.1.34697.2.3", "1.3.6.1.4.1.34697.2.4", "1.2.40.0.17.1.22", "2.16.578.1.26.1.3.3", "1.3.6.1.4.1.17326.10.14.2.1.2", "1.3.6.1.4.1.17326.10.8.12.1.2", "1.3.6.1.4.1.6449.1.2.1.5.1", "2.16.840.1.114412.2.1", "2.16.840.1.114412.1.3.0.2", "2.16.528.1.1001.1.1.1.12.6.1.1.1", "2.16.840.1.114028.10.1.2", "0.4.0.2042.1.4", "0.4.0.2042.1.5", "1.3.6.1.4.1.13177.10.1.3.10", "1.3.6.1.4.1.14370.1.6", "1.3.6.1.4.1.4146.1.1", "2.16.840.1.114413.1.7.23.3", "1.3.6.1.4.1.14777.6.1.1", "2.16.792.1.2.1.1.5.7.1.9", "1.3.6.1.4.1.22234.2.5.2.3.1", "1.3.6.1.4.1.782.1.2.1.8.1", "1.3.6.1.4.1.8024.0.2.100.1.2", "1.2.392.200091.100.721.1", "2.16.840.1.114414.1.7.23.3", "1.3.6.1.4.1.23223.2", "1.3.6.1.4.1.23223.1.1.1", "2.16.756.1.83.21.0", "2.16.756.1.89.1.2.1.1", "2.16.840.1.113733.1.7.48.1", "2.16.840.1.114404.1.1.2.4.1", "2.16.840.1.113733.1.7.23.6", "1.3.6.1.4.1.6334.1.100.1", "2.16.840.1.114171.500.9", "1.3.6.1.4.1.36305.2");

      function get(&$var, $default=null) {
        return isset($var) ? $var : $default;
      }

      function bcdechex($dec) {
        $hex = '';
        do {    
          $last = bcmod($dec, 16);
          $hex = dechex($last).$hex;
          $dec = bcdiv(bcsub($dec, $last), 16);
        } while($dec>0);
        return $hex;
      }
      function startsWith($haystack, $needle) {
        // search backwards starting from haystack length characters from the end
        return $needle === "" || strrpos($haystack, $needle, -strlen($haystack)) !== FALSE;
      }
      function endsWith($haystack, $needle) {
        // search forward starting from end minus needle length characters
        return $needle === "" || strpos($haystack, $needle, strlen($haystack) - strlen($needle)) !== FALSE;
      }

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

      function crl_verify($raw_cert_data, $verbose=true) {
        global $random_blurp;
        $cert_data = openssl_x509_parse($raw_cert_data);
        $cert_serial_nm = strtoupper(bcdechex($cert_data['serialNumber']));   
        $crl_uris = [];
        $crl_uri = explode("\nFull Name:\n ", $cert_data['extensions']['crlDistributionPoints']);
        foreach ($crl_uri as $key => $uri) {
          if (!empty($uri) ) {
            $uri = explode("URI:", $uri);
            foreach ($uri as $key => $crluri) {
              if (!empty($crluri) ) {
                $crl_uris[] = preg_replace('/\s+/', '', $crluri);
              }
            }
          }
        }
        foreach ($crl_uris as $key => $uri) {
          if (!empty($uri)) {
            if (0 === strpos($uri, 'http')) {
              $fp = fopen ("/tmp/" . $random_blurp .  "." . $key . ".crl", 'w+');
              $ch = curl_init(($uri));
              curl_setopt($ch, CURLOPT_TIMEOUT, 5);
              curl_setopt($ch, CURLOPT_FILE, $fp);
              curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
              if(curl_exec($ch) === false)
              {
                echo '<pre>Curl error: ' . htmlspecialchars(curl_error($ch)) ."</pre>";
              }
              curl_close($ch);
              if(stat("/tmp/" . $random_blurp .  "." . $key . ".crl")['size'] < 10 ) {
                return false;
              } 
              $crl_text = shell_exec("openssl crl -noout -text -inform der -in /tmp/" . $random_blurp .  "." . $key . ".crl 2>&1");

              $crl_last_update = shell_exec("openssl crl -noout -lastupdate -inform der -in /tmp/" . $random_blurp .  "." . $key . ".crl");

              $crl_next_update = shell_exec("openssl crl -noout -nextupdate -inform der -in /tmp/" . $random_blurp .  "." . $key . ".crl");

              unlink("/tmp/" . $random_blurp .  "." . $key . ".crl");

              if ( strpos($crl_text, "unable to load CRL") === 0 ) {
                if ( $verbose ) {
                  $result = "<span class='text-danger glyphicon glyphicon-exclamation-sign'></span> - <span class='text-danger'>CRL invalid. (" . $uri . ")</span><br><pre> " . htmlspecialchars($crl_text) . "</pre>";
                    return $result;
                } else {
                  $result = "<span class='text-danger glyphicon glyphicon-remove'></span>";
                  return $result;
                }
              }
              
              $crl_info = explode("Revoked Certificates:", $crl_text)[0];

              $crl_certificates = explode("Revoked Certificates:", $crl_text)[1];

              $crl_certificates = explode("Serial Number:", $crl_certificates); 
              $revcert = array('bla' => "die bla");
              foreach ($crl_certificates as $key => $revoked_certificate) {
                if (!empty($revoked_certificate)) {
                  $revcert[str_replace(" ", "", explode("\n", $revoked_certificate)[0])] = str_replace("        Revocation Date: ", "", explode("\n", $revoked_certificate)[1]);
                }
              }
              if( array_key_exists($cert_serial_nm, $revcert) ) {
                if ( $verbose ) {
                  $result = "<span class='text-danger glyphicon glyphicon-exclamation-sign'></span> - <span class='text-danger'>REVOKED on " . $revcert[$cert_serial_nm] . ". " . $uri . "</span><br><pre>        " . $crl_last_update . "        " . $crl_next_update . "</pre>";
                } else {
                  $result = "<span class='text-danger glyphicon glyphicon-remove'></span>";
                }
              } else {
                if ( $verbose ) {
                  $result = "<span class='text-success glyphicon glyphicon-ok-sign'></span> <span class='text-success'> - " . $uri . "</span><br><pre>        " . $crl_last_update . "        " . $crl_next_update . "</pre>";
                } else {
                  $result = "<span class='text-success glyphicon glyphicon-ok'></span>";
                }
              }
              return $result;
            }
          }
        }
      }

      function fixed_gethostbyname($host) {
          $ip = gethostbyname($host);
          if ($ip != $host) { 
            return $ip; 
          } else {
            return false;
          }
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

//echo htmlspecialchars('openssl ocsp -no_nonce -CAfile '.$root_ca.' -issuer '.$tmp_dir.$random_blurp.'.cert_issuer.pem -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri).'" 2>&1');

        $output = shell_exec('openssl ocsp -no_nonce -CAfile '.$root_ca.' -issuer '.$tmp_dir.$random_blurp.'.cert_issuer.pem -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri) . '" 2>&1');
        $filter_output = shell_exec('openssl ocsp -no_nonce -CAfile '.$root_ca.' -issuer '.$tmp_dir.$random_blurp.'.cert_issuer.pem -cert '.$tmp_dir.$random_blurp.'.cert_client.pem -url "'. escapeshellcmd($ocsp_uri) . '" 2>&1 | grep -v -e "to get local issuer certificate" -e "signer certificate not found" -e "Response Verify" -e "'. $tmp_dir.$random_blurp.'.cert_client.pem"');

        $lines = array();
        $output = preg_replace("/[[:blank:]]+/"," ", $output);
        $ocsp_status_lines = explode("\n", $output);
        $ocsp_status_lines = array_map('trim', $ocsp_status_lines);
        foreach($ocsp_status_lines as $line) {
          if(endsWith($line, ":") == false) {
            list($k, $v) = explode(":", $line);
            $lines[trim($k)] = trim($v);
          }
        }  

        $result = array("This Update" => $lines["This Update"],
          "Next Update" => $lines["Next Update"],
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

      function server_http_headers($host, $port){
          stream_context_set_default(
            array("ssl" => 
              array("verify_peer" => false,
                "capture_session_meta" => true,
                "verify_peer_name" => false,
                "allow_self_signed" => true,
                "sni_enabled" => true),
              'http' => array(
              'method' => 'HEAD'
              )
            )
          );
        $headers = get_headers("https://$host:$port", 1);
        if (!empty($headers)) {
          return $headers;
        }
      }
      
      function ssl_conn_protocols($host, $port){

        $results = array('sslv3' => false, 
                         'tlsv1.0' => false,
                         'tlsv1.1' => false,
                         'tlsv1.2' => false);

        $stream_sslv3 = stream_context_create (array("ssl" => 
          array("verify_peer" => false,
            "capture_session_meta" => true,
            "verify_peer_name" => false,
            "allow_self_signed" => true,
            'crypto_method' => STREAM_CRYPTO_METHOD_SSLv3_CLIENT,
            "sni_enabled" => true)));
        $read_stream_sslv3 = stream_socket_client("sslv3://$host:$port", $errno, $errstr, 2, STREAM_CLIENT_CONNECT, $stream_sslv3);
        if ( $read_stream_sslv3 === false ) {
          $results['sslv3'] = false;
        } else {
          $results['sslv3'] = true;
        }

        $stream_tlsv10 = stream_context_create (array("ssl" => 
          array("verify_peer" => false,
            "capture_session_meta" => true,
            "verify_peer_name" => false,
            "allow_self_signed" => true,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv_1_0_CLIENT,
            "sni_enabled" => true)));
        $read_stream_tlsv10 = stream_socket_client("tlsv1.0://$host:$port", $errno, $errstr, 2, STREAM_CLIENT_CONNECT, $stream_tlsv10);
        if ( $read_stream_tlsv10 === false ) {
          $results['tlsv1.0'] = false;
        } else {
          $results['tlsv1.0'] = true;
        }

        $stream_tlsv11 = stream_context_create (array("ssl" => 
          array("verify_peer" => false,
            "capture_session_meta" => true,
            "verify_peer_name" => false,
            "allow_self_signed" => true,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv_1_1_CLIENT,
            "sni_enabled" => true)));
        $read_stream_tlsv11 = stream_socket_client("tlsv1.1://$host:$port", $errno, $errstr, 2, STREAM_CLIENT_CONNECT, $stream_tlsv11);
        if ( $read_stream_tlsv11 === false ) {
          $results['tlsv1.1'] = false;
        } else {
          $results['tlsv1.1'] = true;
        }

        $stream_tlsv12 = stream_context_create (array("ssl" => 
          array("verify_peer" => false,
            "capture_session_meta" => true,
            "verify_peer_name" => false,
            "allow_self_signed" => true,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv_1_2_CLIENT,
            "sni_enabled" => true)));
        $read_stream_tlsv12 = stream_socket_client("tlsv1.2://$host:$port", $errno, $errstr, 2, STREAM_CLIENT_CONNECT, $stream_tlsv12);
        if ( $read_stream_tlsv12 === false ) {
          $results['tlsv1.2'] = false;
        } else {
          $results['tlsv1.2'] = true;
        }

        return $results;
      }

      function ssl_conn_metadata($host, $port, $chain=null) {
        $stream = stream_context_create (array("ssl" => 
          array("verify_peer" => false,
            "capture_session_meta" => true,
            "verify_peer_name" => false,
            "allow_self_signed" => true,
            "sni_enabled" => true)));
        $read_stream = stream_socket_client("ssl://$host:$port", $errno, $errstr, 2, STREAM_CLIENT_CONNECT, $stream);
        if ( $read_stream === false ) {
          return false;
        } else {
          $context = stream_context_get_params($read_stream);
          $context_meta = stream_context_get_options($read_stream)['ssl']['session_meta'];
          $cert_data = openssl_x509_parse($context["options"]["ssl"]["peer_certificate"])[0];

          if ($context_meta) { 
            ?>
            <h3>Connection Data</h3>
            <table class="table table-striped table-bordered">
              <tbody>
                <tr>
                  <td colspan="2"><strong>Connection Data</strong></td>
                </tr>
                <?php
                  if ( $chain ) {
                ?>
                  <tr>
                     <td>Chain sent by Server (in server order)</td>
                    <td style="font-family: monospace;">
                    <?php
                    foreach ($chain as $key => $cert) {
                      if ( $key == 10) {
                        echo "<span class='text-danger'>Error: Certificate chain to large.</span><br>";
                        continue;
                      }
                      if ( $key > 10) {
                        continue;
                      }
                      if (openssl_x509_parse($cert)['issuer']['CN'] && openssl_x509_parse($cert)['subject']['CN']) {
                        echo "Name...........: <i>";
                        echo htmlspecialchars(openssl_x509_parse($cert)['subject']['CN']);
                        echo " </i><br>Issued by......:<i> ";
                        echo htmlspecialchars(openssl_x509_parse($cert)['issuer']['CN']);
                        echo "</i><br>";
                      }
                    }
                       ?>
                    </td>
                  </tr>

                <?php
                  }
                  if ( fixed_gethostbyname($host) ) {
                ?>
                <tr>
                  <td>IP / Hostname</td>
                  <td>
                    <?php 
                      echo fixed_gethostbyname($host);
                      echo " - ";
                      echo gethostbyaddr(fixed_gethostbyname($host));
                    ?>
                  </td>
                </tr>
                <?php
                  }
                ?>
                <tr>
                  <td>Protocol</td>
                  <td>
                    <?php
                    $protocols = ssl_conn_protocols($host, $port);
                    foreach (array_reverse($protocols) as $key => $value) {
                      if ( $value == true ) {
                        if ( $key == "tlsv1.2") {
                          echo '<p><span class="text-success glyphicon glyphicon-ok"></span> - <span class="text-success">TLSv1.2 (Supported)</span></p>';
                        } else if ( $key == "tlsv1.1") {
                          echo '<p><span class="glyphicon glyphicon-ok"></span> - TLSv1.1 (Supported)</p>';
                        } else if ( $key == "tlsv1.0") {
                          echo '<p><span class="glyphicon glyphicon-ok"></span> - TLSv1.0 (Supported)</p>';
                        } else if ( $key == "sslv3") {
                          echo '<p><span class="text-danger glyphicon glyphicon-ok"></span> - <span class="text-danger">SSLv3 (Supported)</span></p>';
                        } else {
                          echo '<p><span class="glyphicon glyphicon-ok"></span> - <span>'.$key.' (Supported)</span></p>';
                        }
                      } else {
                        if ( $key == "tlsv1.2") {
                          echo '<p><span class="text-danger glyphicon glyphicon-remove"></span> - <span class="text-danger">TLSv1.2 (Not supported)</span></p>';
                        } else if ( $key == "tlsv1.1") {
                          echo '<p><span class="glyphicon glyphicon-remove"></span> - TLSv1.1  (Not supported)</p>';
                        } else if ( $key == "tlsv1.0") {
                          echo '<p><span class="glyphicon glyphicon-remove"></span> - TLSv1.0  (Not supported)</p>';
                        } else if ( $key == "sslv3") {
                          echo '<p><span class="text-success glyphicon glyphicon-remove"></span> - <span class="text-success">SSLv3 (Not supported)</span></p>';
                        } else {
                          echo '<p><span class="glyphicon glyphicon-remove"></span> - <span>'.$key.'(Not supported)</span></p>';
                        }
                      }
                    }
                    ?>

                  </td>
                </tr>
                <tr>
                  <td>Ciphersuite</td>
                  <td>
                    <?php            
                    echo htmlspecialchars($context_meta['cipher_name']);
                    echo " (".htmlspecialchars($context_meta['cipher_bits'])." bits)";
                    ?>
                  </td>
                </tr>
                <?php
                  $headers = server_http_headers($host, $port);
                ?>
                <tr>
                  <td><a href="https://raymii.org/s/tutorials/HTTP_Strict_Transport_Security_for_Apache_NGINX_and_Lighttpd.html">Strict Transport Security</a></td>
                  <td>
                    <?php 
                    if ( $headers["Strict-Transport-Security"] ) {
                      if ( is_array($headers["Strict-Transport-Security"])) {
                        echo htmlspecialchars(substr($headers["Strict-Transport-Security"][0], 0, 50));
                        echo "<br > <i>HSTS header was found multiple times. Only showing the first one.</i>";
                      } else {
                        echo htmlspecialchars(substr($headers["Strict-Transport-Security"], 0, 50));
                      }
                    } else {
                      echo '<span class="text-danger glyphicon glyphicon-remove"></span> - <span class="text-danger">Not Set</span>';
                    }
                    ?>
                  </td>
                </tr>
                <tr>
                  <td><a href="https://raymii.org/s/articles/HTTP_Public_Key_Pinning_Extension_HPKP.html">HTTP Public Key Pinning Extension (HPKP)</a></td>
                  <td>
                    <?php 
                    if ( $headers["Public-Key-Pins"] ) {
                      if ( is_array($headers["Public-Key-Pins"])) {
                        echo htmlspecialchars(substr($headers["Public-Key-Pins"][0], 0, 255));
                        echo "<br > <i>HPKP header was found multiple times. Only showing the first one.</i>";
                      } else {
                        echo htmlspecialchars(substr($headers["Public-Key-Pins"], 0, 255));
                      }
                    } else {
                      echo '<span>Not Set</span>';
                    }
                    ?>
                    <?php 
                    if ( $headers["Public-Key-Pins-Report-Only"] ) {
                      echo "<b>Report Only</b>: ";
                      if ( is_array($headers["Public-Key-Pins-Report-Only"])) {
                        echo htmlspecialchars(substr($headers["Public-Key-Pins-Report-Only"][0], 0, 255));
                        echo "<br > <i>HPKP Report Only header was found multiple times. Only showing the first one.</i>";
                      } else {
                        echo htmlspecialchars(substr($headers["Public-Key-Pins-Report-Only"], 0, 255));
                      }
                    } 
                    ?>
                  </td>
                </tr>
                <tr>
                  <td>OCSP Stapling</td>
                  <td>
                  <?php 
                    $stapling = ocsp_stapling($host,$port);
                    if($stapling["working"] == 1) {
                      echo "<table class='table'>";
                      foreach ($stapling as $key => $value) {
                        if ($key != "working") {
                          echo "<tr><td>" . $key . "</td><td>" . $value . "</td></tr>";
                        }
                      } 
                      echo "</table>";
                    } else {
                      echo "No response received.";
                    }
                  ?>
                  </td>
                </tr>
                <tr>
                  <td>This Server' OpenSSL Version</td>
                  <td>
                  <?php
                  echo htmlspecialchars(shell_exec("openssl version"));
                  ?>
                  </td>
                </tr>
                <tr>
                  <td>This Server' Date (RFC 2822)</td>
                  <td>
                  <?php
                  echo htmlspecialchars(shell_exec("date --rfc-2822"));
                  ?>
                  </td>
                </tr>
              </tbody>
            </table>
            <?php
          } else {
            return false;
          }
        }
      }

      function cert_signature_algorithm($raw_cert_data) {
          $cert_read = openssl_x509_read($raw_cert_data);
          openssl_x509_export($cert_read, $out, FALSE);
          $signature_algorithm = null;
          if(preg_match('/^\s+Signature Algorithm:\s*(.*)\s*$/m', $out, $match)) $signature_algorithm = $match[1];
          return($signature_algorithm);
      }

      function cert_parse($raw_cert_data, $raw_next_cert_data=null, $csr=false, $host=null, $port=null, $is_issuer=false) {
        global $random_blurp;
        global $ev_oids;

        if ($csr == true && strpos($raw_cert_data, "BEGIN CERTIFICATE REQUEST") !== false) { 
          ?>
          <table class="table table-striped table-bordered">
            <tr>
              <td colspan="2"><strong>Certificate Data</strong></td>
            </tr>
            <?php
            $cert_data = openssl_csr_get_public_key($raw_cert_data);

            $cert_details = openssl_pkey_get_details($cert_data);
            $cert_key = $cert_details['key'];
            $cert_subject = openssl_csr_get_subject($raw_cert_data);

            foreach ($cert_subject as $key => $value) {
              echo "<tr><td>";
              switch ($key) {
                case 'C':
                echo "Country";
                break;
                case 'ST':
                echo "State";
                break;
                case 'L':
                echo "City";
                break;
                case 'O':
                echo "Organization";
                break;
                case 'OU':
                echo "Organizational Unit";
                break;
                case 'CN':
                echo "Common Name";
                break;
                case 'mail':
                echo "Email Address";
                break;
                default:
                echo htmlspecialchars($key);
                break;
              }

              echo "</td><td>";
              switch ($key) {
                case 'C':
                echo htmlspecialchars($value);
                echo ' <img src="blank.gif" class="flag flag-';
                echo strtolower(htmlspecialchars($value)); 
                echo '" alt="" />';
                break;
                case 'DC':
                foreach ($value as $key => $value) {
                  echo htmlspecialchars($value) . ".";
                }
                break;
                default:
                if (is_array($value)) {
                  foreach ($value as $key => $value) {
                    echo htmlspecialchars($value) . " ";
                  }
                } else {
                  echo htmlspecialchars($value);
                }
                break;
              }

              echo "</td></tr>\n";
            }
            echo "</table>";
            continue;
          } else {
            $cert_data = openssl_x509_parse($raw_cert_data);
          }
          if (empty($cert_data)) {
            echo "Data not valid.";
            continue;
          }
          ?>
          <table class="table table-striped table-bordered">
            <tr>
              <td colspan="2"><strong>Certificate Data</strong></td>
            </tr>
            <?php
            $next_cert_data = openssl_x509_parse($raw_next_cert_data);
            $today = date("Y-m-d");
            echo "<tr><td colspan='2'>\n";
            echo "<table class='table'>\n";
            echo "<thead><tr>\n";
            echo "<th>Hostname</th>\n";
            echo "<th>Expired</th>\n";
            echo "<th>Issuer</th>\n";
            echo "<th>CRL</th>\n";
            echo "<th>OCSP</th>\n";
            echo "<th>Signing Type</th>\n";
            echo "</tr>\n</thead>\n<tbody>\n<tr>";
            // hostname
            if ($is_issuer == false) {
              if ($csr == false) {
                if ($cert_data['subject']['CN']) {
                  if ( verify_certificate_hostname($raw_cert_data, $host, $port) ) {
                    echo '<td><h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1></td>';
                  } else {
                    echo '<td><h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1></td>';
                  }
                }
              } else {
                echo "<td></td>";
              }
            } else {
              echo "<td></td>";
            }
// expired
            if ( $today > date(DATE_RFC2822,$cert_data['validFrom_time_t']) || strtotime($today) < strtotime(date(DATE_RFC2822,$cert_data['validTo_time_t'])) ) {
              echo '<td><h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1></td>';
            } else {
              echo '<td><h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1></td>';
            }
// issuer
            if ($raw_next_cert_data) {
              if (verify_cert_issuer_by_subject_hash($raw_cert_data, $raw_next_cert_data) ) {
                echo '<td><h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1></td>';
              } else {
                echo '<td><h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1></td>';
              }
            } else {
              echo '<td> </td>';
            }
// crl
            if ( !empty($cert_data['extensions']['crlDistributionPoints']) ) {
              echo "<td><h1>" . crl_verify($raw_cert_data, false) . " &nbsp; </h1></td>";
            } else {
              echo '<td> </td>';
            }
// ocsp
            if ( !empty($cert_data['extensions']['authorityInfoAccess']) && !empty($next_cert_data) ) {
              echo "<td>";
              $ocsp_uri = explode("OCSP - URI:", $cert_data['extensions']['authorityInfoAccess'])[1];
              $ocsp_uri = explode("\n", $ocsp_uri)[0];
              $ocsp_uri = explode(" ", $ocsp_uri)[0];
              if (!empty($ocsp_uri)) {
                $ocsp_result = ocsp_verify($raw_cert_data, $raw_next_cert_data);
                if ($ocsp_result["ocsp_verify_status"] == "good") { 
                  echo '<h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1>';
                } else if ($ocsp_result["ocsp_verify_status"] == "revoked") {
                  echo '<h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1>';
                } else {
                  echo '<h1><span class="text-danger glyphicon glyphicon-question-sign"></span>&nbsp;</h1>';
                }
              } else {
                  echo "<td></td>";
              }
              echo "</td>";
            } else {
              echo "<td> </td>";
            }
            // self signed/ca/ca root
            if (strpos($cert_data['extensions']['basicConstraints'], "CA:TRUE") !== false && $cert_data['issuer']['CN'] == $cert_data['subject']['CN'] ) {
              echo '<td><span class="text-success">CA Root Certificate</span></td>';
            } else if (strpos($cert_data['extensions']['basicConstraints'], "CA:TRUE") !== false) {
              echo '<td><span class="text-success">CA Certificate</span></td>';
            } else if ($cert_data['issuer']['CN'] == $cert_data['subject']['CN']) {
              echo '<td><span class="text-danger">Self Signed</span></td>';
            } else {
              echo "<td>Signed by CA</td>";
            }
            echo "</tr>";
            echo "</tbody></table>";
            echo "</td></tr>";


            if (!empty($cert_data['subject']) ) {
              foreach ($cert_data['subject'] as $key => $value) {
                echo "<tr><td>";
                switch ($key) {
                  case 'C':
                  echo "Country";
                  break;
                  case 'ST':
                  echo "State";
                  break;
                  case 'L':
                  echo "City";
                  break;
                  case 'O':
                  echo "Organization";
                  break;
                  case 'OU':
                  echo "Organizational Unit";
                  break;
                  case 'CN':
                  echo "Common Name";
                  break;
                  case 'mail':
                  echo "Email Address";
                  break;
                  case 'businessCategory':
                  echo "Business Type";
                  break;
                  default:
                  echo htmlspecialchars($key);
                  break;
                }
                echo "</td><td>";
                switch ($key) {
                  case 'C':
                  echo htmlspecialchars($value);
                  echo ' <img src="blank.gif" class="flag flag-';
                  echo strtolower(htmlspecialchars($value)); 
                  echo '" alt="" />';
                  break;
                  case 'DC':
                  foreach ($value as $key => $value) {
                    echo htmlspecialchars($value) . ".";
                  }
                  break;
                  default:
                  if (is_array($value)) {
                    foreach ($value as $key => $value) {
                      echo htmlspecialchars($value) . " ";
                    }
                  } else {
                    echo htmlspecialchars($value);
                  }
                  break;
                }
                echo "</td></tr>\n";
              }


            }
            if (!empty($cert_data['extensions']['subjectAltName'])) {
              ?>
              <tr>
                <td>Subject Alternative Names</td>
                <td>
                  <?php 
                  foreach ( explode("DNS:", $cert_data['extensions']['subjectAltName']) as $altName ) {
                    if ( !empty(str_replace(',', " ", "$altName"))) {
                      echo htmlspecialchars(str_replace(',', " ", "$altName"));
                      echo "<br>";
                    }
                  } 
                ?>
              </td>
            </tr>
            <?php
            }
            ?>
            <tr>
              <td>Type</td>
              <td>
                <?php              
                if ( array_search(explode("Policy: ", explode("\n", $cert_data['extensions']['certificatePolicies'])[0])[1], $ev_oids) ) {
                  echo '<span class="text-success">Extended Validation</span>';
                } else if ( isset($cert_data['subject']['O'] ) ) {
                  echo "Organisation Validation";
                } else if ( isset($cert_data['subject']['CN'] ) ) {
                  echo "Domain Validation";
                }
                ?>
              </td>
            </tr>
            <tr>
              <td>Full Subject</td>
              <td><?php echo htmlspecialchars($cert_data['name']); ?></td>
            </tr>
            <tr>
              <td colspan="2"><strong>Issuer</strong></td>
            </tr>
            <?php 
            if (!empty($cert_data['issuer']) ) {
              foreach ($cert_data['issuer'] as $key => $value) {
                echo "<tr><td>";
                switch ($key) {
                  case 'C':
                  echo "Country";
                  break;
                  case 'ST':
                  echo "State";
                  break;
                  case 'L':
                  echo "City";
                  break;
                  case 'O':
                  echo "Organization";
                  break;
                  case 'OU':
                  echo "Organizational Unit";
                  break;
                  case 'CN':
                  echo "Common Name";
                  break;
                  case 'mail':
                  echo "Email Address";
                  break;
                  case 'emailAddress':
                  echo "Email Address";
                  break;
                  default:
                  echo htmlspecialchars($key);
                  break;
                }
                echo "</td><td>";
                switch ($key) {
                  case 'C':
                  echo htmlspecialchars($value);
                  echo ' <img src="blank.gif" class="flag flag-';
                  echo strtolower(htmlspecialchars($value)); 
                  echo '" alt="" />';
                  break;
                  case 'DC':
                  foreach ($value as $key => $value) {
                    echo htmlspecialchars($value) . ".";
                  }
                  break;
                  default:
                  if (is_array($value)) {
                    foreach ($value as $key => $value) {
                      echo htmlspecialchars($value) . " ";
                    }
                  } else {
                    echo htmlspecialchars($value);
                  }
                  break;
                }
                echo "</td></tr>\n";
              }
            }
            ?>
            <tr>
              <td colspan="2"><strong>Validity</strong></td>
            </tr>
            <?php  
            if ( !empty($cert_data['validFrom_time_t']) ) { 
              ?>
              <tr>
                <td>Valid From</td>
                <td>
                  <?php 
                  if ( $today < date(DATE_RFC2822,$cert_data['validFrom_time_t']) ) {
                    echo '<span class="text-success glyphicon glyphicon-ok-sign"></span>';
                    echo '<span class="text-success"> - ';
                  } else {
                    echo '<span class="text-danger glyphicon glyphicon-exclamation-sign"></span>';
                    echo '<span class="text-danger"> - ';

                  }
                  echo htmlspecialchars(date(DATE_RFC2822,$cert_data['validFrom_time_t'])); 
                  echo "</span>";
                  ?>
                </td>
              </tr>

              <?php
            };
            if ( !empty($cert_data['validTo_time_t']) ) { 
              ?>
              <tr>
                <td>Valid Until</td>
                <td>
                  <?php 
                  if ( strtotime($today) < strtotime(date(DATE_RFC2822,$cert_data['validTo_time_t'])) ) {
                    echo '<span class="text-success glyphicon glyphicon-ok-sign"></span>';
                    echo '<span class="text-success"> - ';
                  } else {
                    echo '<span class="text-danger glyphicon glyphicon-exclamation-sign"></span>';
                    echo '<span class="text-danger"> - ';
                  }
                  echo htmlspecialchars(date(DATE_RFC2822,$cert_data['validTo_time_t'])); 
                  echo "</span>";
                  ?>
                </td>
              </tr>
              <?php
            };
            if ( !empty($cert_data['extensions']['crlDistributionPoints']) ) {
              ?>
              <tr>
                <td>CRL</td>
                <td>
                  <?php            
                  echo crl_verify($raw_cert_data);
                  ?>
                </td>
              </tr>
              <?php
            } else {
              echo "<tr><td>CRL</td><td>No CRL URI found in certificate</td></tr>";
            }
            if ( !empty($cert_data['extensions']['authorityInfoAccess']) && !empty($next_cert_data) ) { 
              ?>
              <tr>
                <td>OCSP</td>
                <td>
                  <?php
                  $ocsp_uri = explode("OCSP - URI:", $cert_data['extensions']['authorityInfoAccess'])[1];
                  $ocsp_uri = explode("\n", $ocsp_uri)[0];
                  $ocsp_uri = explode(" ", $ocsp_uri)[0];

                  if ( isset($raw_next_cert_data) && !empty($ocsp_uri) ) {

                    $ocsp_result = ocsp_verify($raw_cert_data, $raw_next_cert_data);
                    if ($ocsp_result["ocsp_verify_status"] == "good") { 
                      echo '<span class="text-success glyphicon glyphicon-ok-sign"></span> - ';
                      echo '<span class="text-success">';
                      echo "This update: " . htmlspecialchars($ocsp_result["This Update"]) . " - ";
                      echo "Next update: " . htmlspecialchars($ocsp_result["Next Update"]) . "</span>";
                    } else if ( $ocsp_result["ocsp_verify_status"] == "revoked") {
                      echo "This update: " . htmlspecialchars($ocsp_result["This Update"]) . " - ";
                      echo "Next update: " . htmlspecialchars($ocsp_result["Next Update"]) . "</span>";
                    } else {
                      echo '<span class="text-danger glyphicon glyphicon-question-sign"></span>';
                      echo '<span class="text-danger">';

                      echo " - " . htmlspecialchars($ocsp_uri) . "</span><br>";
                      echo "<pre>" . htmlspecialchars($ocsp_result["unknown"]) . "</pre>";
                    }
                  } else {
                      echo "No OCSP URI found in certificate";
                  }
                  ?>
                </td>
              </tr>
              <?php 
            } else {
              echo "<tr><td>OCSP</td><td>No OCSP URI found in certificate</td></tr>";
            }
            if ($is_issuer == false && $csr == false) {
              if ($cert_data['subject']['CN']) {
                echo '<tr><td>Hostname</td>';
                if ( verify_certificate_hostname($raw_cert_data, $host, $port) ) {
                  echo "<td><span class='text-success glyphicon glyphicon-ok'></span>\n<span class='text-success'> - ";
                  echo htmlspecialchars($host);
                  echo " found in CN or SAN.</span></td></tr>";
                } else {
                  
                  echo '<td><span class="text-danger glyphicon glyphicon-remove"></span><span class="text-danger"> - ';
                  echo htmlspecialchars($host); 
                  echo ' NOT found in CN or SAN.</span></td></tr>';
                }
              }
            } else {
              if ($csr == false) {
                echo "<tr><td>Hostname</td><td>Not applicable, this seems to be a CA signing certificate.</td></tr>";
              } else {
                echo "<tr><td>Hostname</td><td>Not applicable, this seems to be a CSR.</td></tr>";
              }
            }
            ?>
              <tr>
                <td colspan="2"><strong>Details</strong></td>
              </tr>
              <?php
            if ( !empty($cert_data['purposes']) ) { 
              ?>
              <tr>
                <td>Purposes</td>
                <td>
                  <?php 
                  $purposes_len = count($cert_data['purposes']);
                  foreach ($cert_data['purposes'] as $key => $purpose) {
                    echo htmlspecialchars($purpose[2]);
                    if ( $key != $purposes_len - 1) {
                      echo ", ";
                    }
                  }
                    ?>
                </td>
              </tr>
              <?php 
            };
            if ( !empty($cert_data['serialNumber']) ) { 
              ?>
              <tr>
                <td>Serial</td>
                <td><code>
                  <?php
                  $sn = str_split(strtoupper(bcdechex($cert_data['serialNumber'])), 2);
                  $sn_len = count($sn);
                  foreach ($sn as $key => $s) {
                    echo htmlspecialchars($s);
                    if ( $key != $sn_len - 1) {
                      echo ":";
                    }
                  }
                  ?>
                </code></td>
              </tr>
              <?php 
              }
              ?>
              <tr>
                <td>Key Size / Type</td>
                <td>
                  <?php
                  $key_details = openssl_pkey_get_details(openssl_pkey_get_public($raw_cert_data));

                  if ( $key_details['rsa'] ) {
                    echo $key_details['bits'];
                    echo " bits RSA";
                  } else if ( $key_details['dsa'] ) {
                    echo $key_details['bits'];
                    echo " bits DSA";
                  } else if ( $key_details['dh'] ) {
                    echo $key_details['bits'];
                    echo " bits DH";
                  } else {
                    "Unknown: <pre>" . var_dump(htmlspecialchars($key_details)) . "</pre>";
                  }
                  ?>
                </td>
              </tr>
              <tr>
                <td>Signature Algorithm</td>
                <td>
                  <?php
                    $signature_algorithm = cert_signature_algorithm($raw_cert_data);
                    echo htmlspecialchars($signature_algorithm);
                  ?>
                </td>
              </tr>
              <tr>
                <td>Extensions</td>
                <td>
                  <div class="panel-group" id="accordion<?php echo bcdechex($cert_data['serialNumber']); ?>" role="tablist" aria-multiselectable="true">
                    <div class="panel panel-default">
                      <div class="panel-heading" role="tab" id="heading<?php echo bcdechex($cert_data['serialNumber']); ?>">
                        <h4 class="panel-title">
                          <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#collapse<?php echo bcdechex($cert_data['serialNumber']); ?>" aria-expanded="false" aria-controls="collapse<?php echo bcdechex($cert_data['serialNumber']); ?>">
                            Click to Open/Close
                          </a>
                        </h4>
                      </div>
                      <div id="collapse<?php echo bcdechex($cert_data['serialNumber']); ?>" class="panel-collapse collapse" role="tabpanel" aria-labelledby="heading<?php echo bcdechex($cert_data['serialNumber']); ?>">
                        <div class="panel-body">
                          <?php 
                          foreach ( $cert_data['extensions'] as $name=>$extension ) {
                            if ( !empty(str_replace(',', " ", "$extension"))) {
                              echo "<strong>" . htmlspecialchars("$name") . "</strong>";
                              echo "<pre>";
                              echo htmlspecialchars($extension);
                              echo "</pre>";
                            }
                          } 
                          ?>
                        </div>
                      </div>
                      </div>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
              <?php
            }
          

          if ( !isset($_GET['host']) || !isset($_GET['csr']) ) {
            ?>
            <form class="form-horizontal">
              <p>Fill in either host + port or paste a CSR/Certficiate. Port defaults to 443.<br></p>
              <fieldset>

                <div class="form-group">
                  <label class="col-md-1 control-label" for="host">Host</label>  
                  <div class="col-md-5">
                    <input id="host" name="host" type="text" placeholder="raymii.org" class="form-control input-md" >
                  </div>
                  <label class="col-md-1 control-label" for="port">Port</label>  
                  <div class="col-md-2">
                    <input id="port" name="port" type="text" placeholder="443" class="form-control input-md">
                  </div>
                </div>

                <hr>

                <div class="form-group">
                  <label class="col-md-1 control-label" for="csr">CSR / Certificate</label>
                  <div class="col-md-5">                     
                    <textarea class="form-control" rows=6 id="csr" name="csr"></textarea>
                  </div>
                </div>


                <div class="form-group">
                  <div class="col-md-4 col-md-offset-1">
                    <div class="checkbox">
                      <label for="json">
                        <input type="checkbox" name="json" id="json" value="json">
                        Output JSON
                      </label>
                    </div>
                  </div>
                </div>

                <div class="form-group">
                  <div class="col-md-4">
                    <label class="col-md-2 col-md-offset-1 control-label" for="s"></label>
                    <button id="s" name="s" class="btn btn-primary">Submit</button>
                  </div>
                </div>

              </fieldset>
            </form>


            <?php
          } else {
            $host = mb_strtolower(get($_GET['host']));
            $port = get($_GET['port'], '443');
            $csr = get($_GET['csr'], '');
            if ( !is_numeric($port) ) {
              $port = 443;
            }

            if ( empty($csr) && !empty($host) ) {

              echo "<strong>This tool does not make conclusions. Please check the data and define the validity yourself!</strong>";

              $stream = stream_context_create (array("ssl" => 
                array("capture_peer_cert" => true,
                  "capture_peer_cert_chain" => true,
                  "verify_peer" => false,
                  "capture_session_meta" => true,
                  "verify_peer_name" => false,
                  "allow_self_signed" => true,
                  "sni_enabled" => true)));
              $read_stream = stream_socket_client("ssl://$host:$port", $errno, $errstr, 5,
                STREAM_CLIENT_CONNECT, $stream);

              if ( $read_stream === false ) {
                echo "<span class='text-danger'> Failed to connect:" . htmlspecialchars($errno) ." " . htmlspecialchars($errstr) . "</span>";
                echo "<hr>";

              } else {

                $context = stream_context_get_params($read_stream);

                $context_meta = stream_context_get_options($read_stream)['ssl']['session_meta'];

                $cert_data = openssl_x509_parse($context["options"]["ssl"]["peer_certificate"]);
                $chain_data = $context["options"]["ssl"]["peer_certificate_chain"];

                if ( isset($_GET['json']) ) {
                  foreach ($chain_data as $key=>$chain_cert) {
                    if ( $key == 0) {
                      echo "<p><h2>JSON Certificate</h2><pre>";
                      print(htmlspecialchars(json_encode(openssl_x509_parse($chain_cert), JSON_PRETTY_PRINT)));
                      echo "</pre></p>";

                    } else {
                      echo "<p><h2>JSON Chain ".$key."</h2><pre>";
                      print(htmlspecialchars(json_encode(openssl_x509_parse($chain_cert), JSON_PRETTY_PRINT)));
                      echo "</pre></p>";
                    }
                  }
                } else {

                  if (!empty($chain_data)) {

                    $chain_length = count($chain_data);
                    $chain_arr_keys  = ($chain_data);
                    foreach(array_keys($chain_arr_keys) as $key) {
                      $curr = $chain_data[$key];
                      $next = $chain_data[$key+1];
                      $prev = $chain_data[$key-1];

                      if ($key == 0) {

                        echo ssl_conn_metadata($host, $port, $chain_data);

                        echo "<h2>Certificate for '". htmlspecialchars($host) ."'</h2>";

                        if ( $chain_length > $key) {
                          cert_parse($curr, $next, false, $host, $port, false);
                        } else {
                          cert_parse($curr, null, false, $host, $port, false);
                        }
                      } else {
                        if ($key == 10) {
                          echo "<span class='text-danger'>Error: Certificate Chain to long.</span><br>.";
                          continue;
                        }
                        if ($key > 10) {
                          continue;
                        }
                        echo "<h2>Chain $key</h2>";
                        if ( $chain_length > $key) {
                          cert_parse($curr, $next, false, null, null, true);
                        } else {
                          cert_parse($curr, null, false, null, null, true);
                        }
                      }
                    }
                  }
                }
              }
            } else if (!empty($csr) && empty($host) ) {

              if ( isset($_GET['json']) ) {

                if (strpos($csr, "BEGIN CERTIFICATE REQUEST") !== false) { 
                  echo "<h2>JSON CSR </h2><p><pre>";
                  $cert_data = openssl_csr_get_public_key($csr);
                  $cert_details = openssl_pkey_get_details($cert_data);
                  $cert_key = $cert_details['key'];
                  $cert_subject = openssl_csr_get_subject($csr);
                  print htmlspecialchars(json_encode($cert_subject), JSON_PRETTY_PRINT);
                } else {
                  echo "<h2>JSON Certificate</h2><p><pre>";
                  print htmlspecialchars(json_encode(openssl_x509_parse($csr), JSON_PRETTY_PRINT));
                }

                echo "</pre></p>";

              } else {
                echo "<strong>This tool does not make conclusions. Please check the data and define the validity yourself!</strong><br>\n &nbsp; <br>";
                if (strpos($csr, "BEGIN CERTIFICATE REQUEST") !== false) { 
                  echo "<h2>CSR </h2><p>";
                } else {
                  echo "<h2>Certificate </h2><p>";
                }
                cert_parse($csr, null, true);
              }
            } else {
              echo "<span class='text-danger'> Host or Certificate required.</span>";
              echo "<hr>";
            }
          }
          ?>
        </div>
      </div>
    </div>

    <div class="footer">
      <div class="col-md-6 col-md-offset-1 container">
        <p class="text-muted">By <a href="https://raymii.org/s/software/OpenSSL_Decoder.html">Remy van Elst</a>. License: GNU GPLv3. <a href="https://github.com/RaymiiOrg/ssl-decoder">Source code</a>. <strong><a href="https://cipherli.st/">Strong SSL Ciphers & Config settings @ Cipherli.st</a></strong>. Version: 1.4</p>
      </div>
    </div>
  </body>
  </html>
