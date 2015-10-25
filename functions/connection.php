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

function submitCertToCT($chain, $ct_url) {
  global $timeout;
  $ct_chain = array('chain' => []);
  foreach ($chain as $key => $value) {
    $string = $value['key']['certificate_pem'];
    $pattern = '/-----(.*)-----/';
    $replacement = '';
    $string = preg_replace($pattern, $replacement, $string);
    $pattern = '/\n/';
    $replacement = '';
    $string = preg_replace($pattern, $replacement, $string);
    array_push($ct_chain['chain'], $string);    
  }
  $post_data = json_encode($ct_chain);
  $ch = curl_init();  
  curl_setopt($ch, CURLOPT_URL, $ct_url . "/ct/v1/add-chain");
  curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
  curl_setopt($ch, CURLOPT_NOBODY, true);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch, CURLOPT_FAILONERROR, false);
  curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
  curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, true);
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
  curl_setopt($ch, CURLOPT_HEADER, false); 
  curl_setopt($ch, CURLOPT_POST, count($post_data));
  curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);    
  $ct_output = curl_exec($ch);
  curl_close($ch);
  return $ct_output;
}

function fixed_gethostbyname($host) {
  $ips = dns_get_record($host, DNS_A + DNS_AAAA);
  sort($ips);
  foreach ($ips as $key => $value) {
    if ($value['type'] === "AAAA") {
      $ip = $value['ipv6'];
    } elseif ($value['type'] === "A") {
      $ip = $value['ip'];
    } else {
      return false;
    }
  }
  if ($ip != $host) { 
    return $ip; 
  } else {
    return false;
  }
}

function get(&$var, $default=null) {
  return isset($var) ? $var : $default;
}

function server_http_headers($host, $ip, $port){
  global $timeout;
  // first check if server is http. otherwise long timeout.
  $ch = curl_init(("https://" . $ip . ":" . $port));
  curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
  curl_setopt($ch, CURLOPT_NOBODY, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array("Host: $host"));
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch, CURLOPT_FAILONERROR, true);
  curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
  curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
  if(curl_exec($ch) === false) {
      curl_close($ch);
      return false;
  }
  curl_close($ch);

  stream_context_set_default(
    array("ssl" => 
      array("verify_peer" => false,
        "capture_session_meta" => true,
        "verify_peer_name" => false,
        "peer_name" => $host,
        "allow_self_signed" => true,
        "sni_enabled" => true),
      'http' => array(
        'method' => 'GET',
        'max_redirects' => 1,
        'header' => 'Host: '.$host,
        'timeout' => $timeout
        )
      )
    );
  $headers = get_headers("https://$ip:$port", 1);
  if (!empty($headers)) {
    $headers = array_change_key_case($headers, CASE_LOWER);
    return $headers;
  }
}

function ssl_conn_ciphersuites($host, $ip, $port, $ciphersuites) {
  global $timeout;
  $old_error_reporting = error_reporting();
  error_reporting(0); 
  $results = array();
  foreach ($ciphersuites as $value) {
    $results[$value] = false;
    $stream = stream_context_create (array("ssl" => 
    array("verify_peer" => false,
      "verify_peer_name" => false,
      "allow_self_signed" => true,
      "peer_name" => $host,
      'ciphers' => $value,
      "sni_enabled" => true)));
    $read_stream = stream_socket_client("ssl://$ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream);
    if ( $read_stream === false ) {
      $results[$value] = false;
    } else {
      $results[$value] = true;
    }
  }
  error_reporting($old_error_reporting);
  return $results;
}

function test_heartbleed($ip, $port) {
  //this uses an external python2 check to test for the heartblead vulnerability
  global $current_folder;
  global $timeout;
  $exitstatus = 0;
  $output = 0;
  $cmdexitstatus = 0;
  $cmdoutput = 0;
  $result = 0;
  $uuid = gen_uuid();
  $tmpfile = "/tmp/" . $uuid . ".txt";
  # check if python2 is available
  exec("command -v python2 >/dev/null 2>&1", $cmdoutput, $cmdexitstatus);
  if ($cmdexitstatus != 1) {
    //15 is a reasonable timeout. 
    exec("timeout 15 python2 " . getcwd() . "/inc/heartbleed.py " . escapeshellcmd($ip) . " --json \"" . $tmpfile . "\" --threads 1 --port " . escapeshellcmd($port) . " --silent", $output, $exitstatus);
    if (file_exists($tmpfile)) {
      $json_data = json_decode(file_get_contents($tmpfile),true);
      foreach ($json_data as $key => $value) {
        if ($value['status'] == true) {
          $result = "vulnerable";
        } else {
          $result = "not_vulnerable";
        }
      }
      unlink($tmpfile);
    }
  } else {
    $result = "python2error";
  }
  return $result;
}

function heartbeat_test($host, $port) {
  //this tests for the heartbeat protocol extension
  global $random_blurp;
  global $timeout;
  $result = 0;

  $output = shell_exec('echo | timeout ' . $timeout . ' openssl s_client -connect ' . escapeshellcmd($host) . ':' . escapeshellcmd($port) . ' -servername ' . escapeshellcmd($host) . ' -tlsextdebug 2>&1 </dev/null | awk -F\" \'/server extension/ {print $2}\'');

  $output = preg_replace("/[[:blank:]]+/"," ", $output);
  $output = explode("\n", $output);
  $output = array_map('trim', $output);
  if ( in_array("heartbeat", $output) ) {
    $result = 1;
  }
  return $result;
}

function test_sslv2($ip, $port) {
  global $timeout;
  $exitstatus = 0;
  $output = 0;
  exec('echo | timeout ' . $timeout . ' openssl s_client -connect "' . escapeshellcmd($ip) . ':' . escapeshellcmd($port) . '" -ssl2 2>&1 >/dev/null', $output, $exitstatus); 
  if ($exitstatus == 0) { 
    $result = true;
  } else {
    $result = false;
  }
  return $result;
}

function conn_compression($host, $ip, $port) {
  global $timeout;
  if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
    return true;
  }
  $exitstatus = 0;
  $output = 0;
  exec('echo | timeout ' . $timeout . ' openssl s_client -servername "' . escapeshellcmd($host) . '" -connect "' . escapeshellcmd($ip) . ':' . escapeshellcmd($port) . '" -status -tlsextdebug 2>&1 | grep -qe "^Compression: NONE"', $output, $exitstatus); 
  if ($exitstatus == 0) { 
    $result = false;
  } else {
    $result = true;
  }
  return $result;
}

function ssl_conn_protocols($host, $ip, $port) {
  global $timeout;
  $old_error_reporting = error_reporting();
  error_reporting(0); 
  $results = array('sslv2' => false, 
                   'sslv3' => false, 
                   'tlsv1.0' => false,
                   'tlsv1.1' => false,
                   'tlsv1.2' => false);

  $results['sslv2'] = test_sslv2($host, $port);

  $stream_sslv3 = stream_context_create (array("ssl" => 
    array("verify_peer" => false,
      "capture_session_meta" => true,
      "verify_peer_name" => false,
      "peer_name" => $host,
      "allow_self_signed" => true,
      'crypto_method' => STREAM_CRYPTO_METHOD_SSLv3_CLIENT,
      "sni_enabled" => true)));
  $read_stream_sslv3 = stream_socket_client("sslv3://$ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream_sslv3);
  if ( $read_stream_sslv3 === false ) {
    $results['sslv3'] = false;
  } else {
    $results['sslv3'] = true;
  }

  $stream_tlsv10 = stream_context_create (array("ssl" => 
    array("verify_peer" => false,
      "capture_session_meta" => true,
      "verify_peer_name" => false,
      "peer_name" => $host,
      "allow_self_signed" => true,
      'crypto_method' => STREAM_CRYPTO_METHOD_TLSv_1_0_CLIENT,
      "sni_enabled" => true)));
  $read_stream_tlsv10 = stream_socket_client("tlsv1.0://$ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream_tlsv10);
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
      "peer_name" => $host,
      'crypto_method' => STREAM_CRYPTO_METHOD_TLSv_1_1_CLIENT,
      "sni_enabled" => true)));
  $read_stream_tlsv11 = stream_socket_client("tlsv1.1://$ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream_tlsv11);
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
      "peer_name" => $host,
      'crypto_method' => STREAM_CRYPTO_METHOD_TLSv_1_2_CLIENT,
      "sni_enabled" => true)));
  $read_stream_tlsv12 = stream_socket_client("tlsv1.2://$ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream_tlsv12);
  if ( $read_stream_tlsv12 === false ) {
    $results['tlsv1.2'] = false;
  } else {
    $results['tlsv1.2'] = true;
  }
  error_reporting($old_error_reporting);
  return $results;
}

function get_ca_issuer_urls($raw_cert_data) {
  $result = array();
  $authorityInfoAcces = explode("\n", openssl_x509_parse($raw_cert_data)['extensions']['authorityInfoAccess']);
  if (openssl_x509_parse($raw_cert_data)['extensions']['authorityInfoAccess']) {
    foreach ($authorityInfoAcces as $authorityInfoAccess) {
      $crt_uris = explode("CA Issuers - URI:", $authorityInfoAccess);
      foreach ($crt_uris as $key => $crt_uri) {
        foreach (explode("\n", $crt_uri) as $crt_ur) {
          if($crt_ur) {
            if (strpos(strtolower($crt_ur), 'ocsp') === false) {
              array_push($result, $crt_ur);
            }  
          }                
        }
      }
    }
  }
  return $result;
}

function get_ca_issuer_crt($raw_cert_data) {
  //we save certs, so we might have the issuer already.
  //first check that, otherwise get crt from authorityinfoaccess
  global $timeout;
  if (!is_dir('crt_hash')) {
    mkdir('crt_hash');
  }
  // filenames of saved certs are hashes of the asort full subject. 
  $sort_subject = openssl_x509_parse($raw_cert_data)['issuer'];
  asort($sort_subject);
  foreach ($sort_subject as $key => $value) {
    $issuer_full = "/" . $key . "=" . $value . $issuer_full;
  }
  $crt_check_hash = hash("sha256", $issuer_full);
  $crt_check_hash_folder = "crt_hash/";
  $crt_check_hash_file = $crt_check_hash_folder . $crt_check_hash . ".pem";
  if(file_exists($crt_check_hash_file)) {
    //if we already have a PEM file where the subject matches this certs issuer
    //it probably is the correct one. return that and be done with it.
    $crt_data = file_get_contents($crt_check_hash_file);
    $export_pem = "";
    openssl_x509_export($crt_data, $export_pem);
    //make sure it is valid data.
    if($export_pem) {
      $crt_cn = openssl_x509_parse($crt_data)['name'];
      //add start and end for more clarity since this is a copy-pastable thingy.
      $return_crt = "#start " . $crt_cn . "\n" . $export_pem . "#end " . $crt_cn . "\n";
      return $return_crt;
    }
  } else {
    $issuer_urls = get_ca_issuer_urls($raw_cert_data);
    if($issuer_urls) {
      foreach ($issuer_urls as $key => $ca_issuer_url) {
        //if we don't have that cert saved, we check if there is a der file
        //based on the issuer url hash.
        $crt_hash = hash("sha256", $ca_issuer_url);
        $crt_hash_folder = "crt_hash/";
        $crt_hash_file = $crt_hash_folder . $crt_hash . ".der";
        if (!file_exists($crt_hash_file)) {
          //that file is not there, let's get it
          if (0 === strpos($ca_issuer_url, 'http')) {
            $fp = fopen ($crt_hash_file, 'w+');
            $ch = curl_init(($ca_issuer_url));
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_FILE, $fp);
            curl_setopt($ch, CURLOPT_FAILONERROR, true);
            curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
            if(curl_exec($ch) === false) {
              continue;
            }
            curl_close($ch);
            if(stat($crt_hash_file)['size'] < 10 ) {
              //probably a corrypt file. sould be at least +100KB.
                unlink($crt_hash_file);
            }
          }
        } else {
          if (time()-filemtime($crt_hash_file) > 5 * 84600) {
            // file older than 5 days. crt might have changed, retry.
              $content_hash = sha1_file($crt_hash_file);
              rename($crt_hash_file, $crt_hash_folder . $content_hash . "content_hash.der");
              get_ca_issuer_crt($raw_cert_data);
          }
        }
        if (file_exists($crt_hash_file)) {
          //we have a a der file, we need to convert it to pem and return it.
          //dirty way to get pem from der...
          $crt_data = "-----BEGIN CERTIFICATE-----\n" . wordwrap(base64_encode(file_get_contents($crt_hash_file)), 65, "\n", 1) . "\n-----END CERTIFICATE-----";
          $crt_cn = openssl_x509_parse($crt_data)['name'];
          $export_pem = "";
          openssl_x509_export($crt_data, $export_pem);
          //make sure it is valid data.
          if($export_pem) {
            $return_crt = "#start " . $crt_cn . "\n" . $export_pem . "\n#end " . $crt_cn . "\n";
            //add start and end for more clarity since this is a copy-pastable thingy.
            $sort_subject = openssl_x509_parse($crt_data)['subject'];
            asort($sort_subject);
            foreach ($sort_subject as $key => $value) {
              $name_full = "/" . $key . "=" . $value . $name_full;
            }
            $crt_hash = hash("sha256", $name_full);
            $crt_hash_folder = "crt_hash/";
            $crt_hash_file = $crt_hash_folder . $crt_hash . ".pem";
            //if the chain is wrong and we got this certificate
            //via the authorityinfoaccess, we might not get it as a 
            //regular cert via the check. so therefore we save this 
            //as well, via the same mechanism.
            if(file_exists($crt_hash_file)) {
              if (time()-filemtime($crt_hash_file) > 5 * 84600) {
                // file older than 5 days. crt might have changed, retry.
                $content_hash = sha1_file($crt_hash_file);
                rename($crt_hash_file, $crt_hash_folder . $content_hash . "content_hash.pem");
                file_put_contents($crt_hash_file, $export_pem);
              }
            } else {
              file_put_contents($crt_hash_file, $export_pem);
            }
            if(stat($crt_hash_file)['size'] < 10 ) {
              //probably a corrypt file. sould be at least +100KB.
              unlink($crt_hash_file);
            }
          }
        }
        return $return_crt;
      }            
    }
  }
}


function get_issuer_chain($raw_cert_data, $number=1, $result=null) {
  global $max_chain_length;
  if ($result['complete'] == 'yes') {
    return $result;
  }
  if ($number > $max_chain_length) {
    $result['complete'] == 'error';
    return $result;
  }
  $number += 1;

  if (!is_array($result)) {
    $result = array('certs' => array(), 'complete' => 'false');
  }

  $sort_subject = openssl_x509_parse($raw_cert_data)['subject'];
  asort($sort_subject);
  foreach ($sort_subject as $key => $value) {
    $subject_full = "/" . $key . "=" . $value . $subject_full;
  }
  $sort_issuer = openssl_x509_parse($raw_cert_data)['issuer'];
  asort($sort_issuer);
  foreach ($sort_issuer as $key => $value) {
    $issuer_full = "/" . $key . "=" . $value . $issuer_full;
  }
  if($issuer_full == $subject_full && $result) {
    $result['complete'] == 'yes';
    return $result;
  } 
  $this_issuer = get_ca_issuer_crt($raw_cert_data);
  if($this_issuer) {
    array_push($result['certs'], $this_issuer);
    $result = get_issuer_chain($this_issuer, $number, $result);
    return $result;
  } else {
    return $result;
  }
  return $result;
}

function ssl_conn_metadata($data,$fastcheck=0) {
  global $random_blurp;
  global $current_folder;
  $chain_length = count($data["chain"]);
  echo "<section id='conndata'>";
  if (is_array($data["warning"]) && count($data["warning"]) >= 1) {
    $data["warning"] = array_unique($data["warning"]);
    if (count($data["warning"]) == 1) {
      echo "<h3>" . count($data["warning"]) . " warning!</h3>";
    } else {
      echo "<h3>" . count($data["warning"]) . " warnings!</h3>";
    }
    foreach ($data["warning"] as $key => $value) {
      echo "<div class='alert alert-danger' role='alert'>";
      echo $value;
      echo "</div>";
    }
  }
  echo "<table class='table table-striped table-bordered'>";
  echo "<tbody>";
  echo "<tr>";
  echo "<td colspan='2'><strong>Connection Data</strong></td>";
  echo "</tr>";
  echo "<tr>";
  // chain
  echo "<td>Chain sent by Server <br>(in server order)</td>";
  echo "<td style='font-family: monospace;'>";
  foreach ($data["chain"] as $key => $value) {
    if (!empty($value['name'])) {
      echo "Name...........: <i>";
      echo htmlspecialchars(htmlspecialchars($value['name']));
      echo " </i><br>Issued by......:<i> ";
      echo htmlspecialchars(htmlspecialchars($value['issuer']));
      echo "</i><br>";
    }
    if (isset($value["error"])) {
      echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>Error: Issuer does not match the next certificate CN. Chain order is probably wrong.</span><br><br>";
    }
  }
  echo "<br>";
  if ($data["validation"]["status"] == "failed") {
    echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>Validating certificate chain failed:</span><br>";
    echo "<pre>";
    echo htmlspecialchars($data["validation"]["error"]);
    echo "</pre>";
  } else {
    echo "<span class='text-success glyphicon glyphicon-ok'></span> - <span class='text-success'>Successfully validated certificate chain.</span><br>";
  }
  echo "</td>";
  echo "</tr>";

  // correct chain
  if ($fastcheck == 0 && $data["validation"]["status"] == "failed" && is_array($data["validation"]["correct_chain"])) {
    echo "<tr>";
    echo "<td><strong>Correct Chain</strong></td>";
    echo "<td>";
    echo "<p><strong>The validation of this certificate failed. This might be because of an incorrect or incomplete CA chain. Based on the '<code>authorityInfoAccess</code>' extension and earlier saved certificates, the below result probably contains the correct CA Chain, in the correct order, for this certificate. The result also contains your certificate as the first one.</strong><br>";

    echo "<p>This is our best guess at the correct ca signing chain: <br><ul>";
    foreach ($data['validation']['cns'] as $cn_key => $cn_value) {
      foreach ($cn_value as $cnn_key => $cnn_value) {
        echo "<span style='font-family: monospace;'><li>";
        if($cnn_key == 'cn') {
          echo "Name.......: ";
          echo htmlspecialchars($cnn_value);
          echo "</li></span>  ";
        }
        if ($cnn_key == 'issuer') {
          echo "Issued by..: ";
          echo htmlspecialchars($cnn_value);
          echo "</li></span><br>";
        }
      }
    }
    echo "</ul></p>";
    echo "<p>Click below to see the full chain output in PEM format, copy-pastable in most software.</p>";
    ?>
    <div class="panel-group" id="accordion-correct-chain" role="tablist" aria-multiselectable="true">
      <div class="panel panel-default">
        <div class="panel-heading" role="tab" id="heading-correct-chain">
          <h4 class="panel-title">
            <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#collapse-correct-chain" aria-expanded="false" aria-controls="collapse-correct-chain">
              Click to Open/Close
            </a>
          </h4>
        </div>
        <div id="collapse-correct-chain" class="panel-collapse collapse" role="tabpanel" aria-labelledby="heading-correct-chain">
          <div class="panel-body">
    <?php
    echo "<pre>"; 
    foreach ($data['validation']['correct_chain'] as $cert) {
      echo htmlspecialchars($cert);
      echo "<br>";
    }
    echo "</pre>"; 
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</td>";
    echo "</tr>";
  }

  // ip hostname port
  if ( $data["hostname"] ) {
    echo "<tr>";
    echo "<td>IP / Hostname / Port</td>";
    echo "<td>";
    echo htmlspecialchars($data["ip"]);
    echo " - ";
    echo htmlspecialchars($data["hostname"]);
    echo " - ";
    echo htmlspecialchars($data["port"]);
    echo "</td>";
    echo "</tr>";
  }
  if($fastcheck == 0) {
    // protocols
    echo "<tr>";
    echo "<td>Protocols</td>";
    echo "<td>";
    $protocols = $data["protocols"];
    foreach ($protocols as $key => $value) {
      if ( $value == true ) {
        if ( $key == "tlsv1.2") {
          echo '<p><span class="text-success glyphicon glyphicon-ok"></span> - <span class="text-success">TLSv1.2 (Supported)</span></p>';
        } else if ( $key == "tlsv1.1") {
          echo '<p><span class="glyphicon glyphicon-ok"></span> - TLSv1.1 (Supported)</p>';
        } else if ( $key == "tlsv1.0") {
          echo '<p><span class="glyphicon glyphicon-ok"></span> - TLSv1.0 (Supported)</p>';
        } else if ( $key == "sslv3") {
          echo '<p><span class="text-danger glyphicon glyphicon-ok"></span> - <span class="text-danger">SSLv3 (Supported) </span>';
          echo "<a href='https://blog.mozilla.org/security/2014/10/14/the-poodle-attack-and-the-end-of-ssl-3-0/' data-toggle='tooltip' data-placement='top' title='SSLv3 is old and broken. It makes you vulerable for the POODLE attack. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a></p>";
        } else if ( $key == "sslv2") {
          echo '<p><span class="text-danger glyphicon glyphicon-ok"></span> - <span class="text-danger">SSLv2 (Supported) </span>';
          echo "<a href='http://www.rapid7.com/db/vulnerabilities/sslv2-and-up-enabled' data-toggle='tooltip' data-placement='top' title='SSLv2 is old and broken. It was replaced by SSLv3 in 1996. It does not support intermediate certs and has flaws in the crypto. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a></p>";
        } else {
          echo '<p><span class="glyphicon glyphicon-ok"></span> - <span>'.$key.' (Supported)</span></p>';
        }
      } else {
        if ( $key == "tlsv1.2") {
          echo '<p><span class="text-danger glyphicon glyphicon-remove"></span> - <span class="text-danger">TLSv1.2 (Not supported)</span> ';
          echo "<a href='http://www.yassl.com/yaSSL/Blog/Entries/2010/10/7_Differences_between_SSL_and_TLS_Protocol_Versions.html' data-toggle='tooltip' data-placement='top' title='TLSv1.2 was released in 2008. It is the most recent and secure version of the protocol. It adds TLS extensions and the AES ciphersuites plus other features and fixes. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a></p>";
        } else if ( $key == "tlsv1.1") {
          echo '<p><span class="glyphicon glyphicon-remove"></span> - TLSv1.1  (Not supported)</p>';
        } else if ( $key == "tlsv1.0") {
          echo '<p><span class="glyphicon glyphicon-remove"></span> - TLSv1.0  (Not supported)</p>';
        } else if ( $key == "sslv3") {
          echo '<p><span class="text-success glyphicon glyphicon-remove"></span> - <span class="text-success">SSLv3 (Not supported)</span></p>';
        } else if ( $key == "sslv2") {
          echo '<p><span class="text-success glyphicon glyphicon-remove"></span> - <span class="text-success">SSLv2 (Not supported)</span></p>';
        } else {
          echo '<p><span class="glyphicon glyphicon-remove"></span> - <span>'.$key.'(Not supported)</span></p>';
        }
      }
    }
    echo "</td>";
    echo "</tr>";
    echo "<tr>";
    echo "<td>SSL Compression</td>";
    echo "<td>";
    if ($data['compression'] == false) {
      echo '<p><span class="text-success glyphicon glyphicon-ok"></span> - <span class="text-success">SSL Compression disabled</span></p>';
    } else {
      echo '<p><span class="text-danger glyphicon glyphicon-remove"></span> - <span class="text-danger">SSL Compression enabled</span> ';

      echo "<a href='https://isecpartners.com/blog/2012/september/details-on-the-crime-attack.aspx' data-toggle='tooltip' data-placement='top' title='SSL Compression makes you vulnerable to the CRIME attack. Click the question mark for more info about it.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a></p>";
    }
    echo "</td>";
    echo "</tr>";
    //ciphersuites
    echo "<tr>";
    echo "<td>Ciphersuites supported by server</td>";
    echo "<td>";
    $bad_ciphersuites = array('ECDHE-RSA-DES-CBC3-SHA',
      'ECDHE-ECDSA-DES-CBC3-SHA',
      'EDH-RSA-DES-CBC3-SHA',
      'EDH-DSS-DES-CBC3-SHA',
      'DH-RSA-DES-CBC3-SHA',
      'DH-DSS-DES-CBC3-SHA',
      'ECDH-RSA-DES-CBC3-SHA',
      'ECDH-ECDSA-DES-CBC3-SHA',
      'DES-CBC3-SHA',
      'EDH-RSA-DES-CBC-SHA',
      'EDH-DSS-DES-CBC-SHA',
      'DH-RSA-DES-CBC-SHA',
      'DH-DSS-DES-CBC-SHA',
      'DES-CBC-SHA',
      'EXP-EDH-RSA-DES-CBC-SHA',
      'EXP-EDH-DSS-DES-CBC-SHA',
      'EXP-DH-RSA-DES-CBC-SHA',
      'EXP-DH-DSS-DES-CBC-SHA',
      'EXP-DES-CBC-SHA',
      'EXP-EDH-RSA-DES-CBC-SHA',
      'EXP-EDH-DSS-DES-CBC-SHA',
      'EXP-DH-RSA-DES-CBC-SHA',
      'EXP-DH-DSS-DES-CBC-SHA',
      'EXP-DES-CBC-SHA',
      'EXP-RC2-CBC-MD5',
      'EXP-RC4-MD5',
      'RC4-MD5',
      'EXP-RC2-CBC-MD5',
      'EXP-RC4-MD5',
      'ECDHE-RSA-RC4-SHA',
      'ECDHE-ECDSA-RC4-SHA',
      'ECDH-RSA-RC4-SHA',
      'ECDH-ECDSA-RC4-SHA',
      'RC4-SHA',
      'RC4-MD5',
      'PSK-RC4-SHA',
      'EXP-RC4-MD5',
      'ECDHE-RSA-NULL-SHA',
      'ECDHE-ECDSA-NULL-SHA',
      'AECDH-NULL-SHA',
      'RC4-SHA',
      'RC4-MD5',
      'ECDH-RSA-NULL-SHA',
      'ECDH-ECDSA-NULL-SHA',
      'NULL-SHA256',
      'NULL-SHA',
      'NULL-MD5');
    foreach ($data["supported_ciphersuites"] as $key => $value) {
      if (in_array($value, $bad_ciphersuites)) {
        $bad_ciphersuite = 1;
        echo "<span class='text-danger glyphicon glyphicon-remove'></span>";
        echo "<span class='text-danger'> ";
        echo htmlspecialchars($value);
        echo "</span>";
      } else {
        echo "<span class='glyphicon glyphicon-minus'></span> ";
        echo htmlspecialchars($value);
      }
      echo "<br>";
    }
    if ($bad_ciphersuite) {
      echo "<p><br>Ciphersuites containing <a href='https://en.wikipedia.org/wiki/Null_cipher'>NULL</a>,";
      echo " <a href='https://en.wikipedia.org/wiki/Export_of_cryptography_from_the_United_States'>EXP(ort)</a>,";
      echo " <a href='https://en.wikipedia.org/wiki/Weak_key'>DES";
      echo " and RC4</a> are marked RED because they are suboptimal.</p>";
    }
    echo "</td>";
    echo "</tr>";
    //tls fallback scsv
    echo "<tr>";
    echo "<td>";
    echo "TLS_FALLBACK_SCSV";
    echo "</td>";
    echo "<td>";

    if ($data["tls_fallback_scsv"] == "supported") {
      echo "<span class='text-success glyphicon glyphicon-ok'></span> - <span class='text-success'>TLS_FALLBACK_SCSV supported. </span>";
    } elseif ($data["tls_fallback_scsv"] == "unsupported") {
      echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>TLS_FALLBACK_SCSV not supported. </span>";
    } else {
      echo "Only 1 protocol enabled, fallback not possible, TLS_FALLBACK_SCSV not required. ";
    }
    echo "<a href='http://googleonlinesecurity.blogspot.nl/2014/10/this-poodle-bites-exploiting-ssl-30.html' data-toggle='tooltip' data-placement='top' title='TLS_FALLBACK_SCSV provides protocol downgrade protection. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a>";
    echo "</td>";
    echo "</tr>";

    //heartbleed
    if ($data['heartbleed'] != 'python2error') {
      echo "<tr>";
      echo "<td>";
      echo "Heartbleed";
      echo "</td>";
      echo "<td>";

      if ($data["heartbleed"] == "not_vulnerable") {
        echo "<span class='text-success glyphicon glyphicon-ok'></span> - <span class='text-success'>Not vulnerable. </span>";
      } elseif ($data["heartbleed"] == "vulnerable") {
        echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>Vulnerable. </span>";
      } 
      echo "<a href='http://heartbleed.com/' data-toggle='tooltip' data-placement='top' title='Heartbleed is a serious vulnerability exposing server memory and thus private data to an attacker. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a>";
      echo "</td>";
      echo "</tr>";
    }

    echo "<tr>";
    echo "<td>";
    echo "Heartbeat Extension";
    echo "</td>";
    echo "<td>";

    if ($data["heartbeat"] == "1") {
      echo "Extension enabled.";
    } else {
      echo "Extenstion not enabled.";
    } 
    echo "</td>";
    echo "</tr>";

    // headers
    echo "<tr>";
    echo "<td>";
    echo "<a href='https://raymii.org/s/tutorials/HTTP_Strict_Transport_Security_for_Apache_NGINX_and_Lighttpd.html'>Strict Transport Security</a>";
    echo "</td>";
    echo "<td>";
    // hsts
    if ( $data["strict_transport_security"] == "not set" ) {
      echo '<span class="text-danger glyphicon glyphicon-remove"></span> - <span class="text-danger">Not Set</span>';
    } else {
      echo "<span class='text-success glyphicon glyphicon-ok'></span> - <span class='text-success'>";
      echo htmlspecialchars($data["strict_transport_security"]);
      echo "</span>";
    }
    echo " <a href='https://raymii.org/s/tutorials/HTTP_Strict_Transport_Security_for_Apache_NGINX_and_Lighttpd.html' data-toggle='tooltip' data-placement='top' title='Strict Transport Security lets visitors know that your website should only be visitid via HTTPS. Click the question mark for more info.'><span class='glyphicon glyphicon-question-sign' aria-hidden='true'></span></a>";
    echo "</td>";
    echo "</tr>";
    echo "<tr>";
    echo "<td>";
    echo "<a href='https://raymii.org/s/articles/HTTP_Public_Key_Pinning_Extension_HPKP.html'>HTTP Public Key Pinning Extension (HPKP)</a>";
    echo "</td>";
    echo "<td>";
    //hpkp
    if ( $data["public_key_pins"] == "not set" ) {
      echo '<span>Not Set</span>';
    } else {
      echo "<span class='text-success glyphicon glyphicon-ok'></span> - <span class='text-success'>";
      echo htmlspecialchars($data["public_key_pins"]);
    }
    if ( $data["public_key-pins_report_only"] ) {
      echo "<b>Report Only</b>: ";
      echo htmlspecialchars($data["public_key_pins_report_only"]);
    }

    echo "</td>";
    echo "</tr>";
    // ocsp stapling
    echo "<tr>";
    echo "<td>OCSP Stapling</td>";
    echo "<td>";
    if (isset($data["ocsp_stapling"]["working"])) {
      if($data["ocsp_stapling"]["working"] == 1) {
        echo "<table class='table'>";
        foreach ($data["ocsp_stapling"] as $key => $value) {
          if ($key != "working") {
            echo "<tr><td>" . htmlspecialchars(ucfirst(str_replace('_', ' ', $key))) . "</td><td>" . htmlspecialchars($value) . "</td></tr>";
          }
        } 
        echo "</table>";
      } else {
        echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>No OCSP stapling response received.</span>";
      }
    } else {
      echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>No OCSP stapling response received.</span>";
    }
    echo "</td>";
  }
  // openssl version
  echo "</tr>";
  echo "<tr>";
  echo "<td>This Server's OpenSSL Version</td>";
  echo "<td>";
  echo htmlspecialchars(shell_exec("openssl version"));
  echo "</td>";
  echo "</tr>";
  echo "<tr>";
  //date
  echo "<td>This Server's Date <br>(RFC 2822)</td>";
  echo "<td>";
  echo htmlspecialchars(shell_exec("date --rfc-2822"));
  echo "</td>";
  echo "</tr>";
  echo "</tbody>";
  echo "</table>";
}

function ssl_conn_metadata_json($host, $ip, $port, $read_stream, $chain_data=null,$fastcheck=0) {
  $result = array();
  global $random_blurp;
  global $current_folder;
  global $timeout;
  global $max_chain_length;
  $context = stream_context_get_params($read_stream);
  $context_meta = stream_context_get_options($read_stream)['ssl']['session_meta'];
  $cert_data = openssl_x509_parse($context["options"]["ssl"]["peer_certificate"])[0];

  if (filter_var(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 )) {
    $result["warning"][] = "You are testing an IPv6 host. Due to <a href=\"https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest\">bugs</a> in OpenSSL's command line tools the results will be inaccurate. Known incorrect are OCSP Stapling, TLS_FALLBACK_SCSV and SSL Compression results, others may also be incorrect.";
  } 
  
  $result["checked_hostname"] = $host;
  //chain
  if (isset($context_meta)) { 
    if (isset($chain_data)) {
      $chain_length = count($chain_data);
      $certificate_chain = array();
      if ($chain_length <= 10) {
        for ($i = 0; $i < $chain_length; $i++) {
          if (openssl_x509_parse($chain_data[$i])['issuer']['CN'] && openssl_x509_parse($chain_data[$i])['subject']['CN']) {
            $result["chain"][$i]["name"] = openssl_x509_parse($chain_data[$i])['subject']['CN'];
            $result["chain"][$i]["issuer"] = openssl_x509_parse($chain_data[$i])['issuer']['CN'];
            $export_pem = "";
            openssl_x509_export($chain_data[$i], $export_pem);
            array_push($certificate_chain, $export_pem);
            if (openssl_x509_parse($chain_data[$i])['issuer']['CN'] == openssl_x509_parse($chain_data[$i + 1])['subject']['CN']){
              continue;
            } else {
              if ($i != $chain_length - 1) {
                $result["chain"][$i]["error"] = "Issuer does not match the next certificate CN. Chain order is probably wrong.";
                $result["warning"][] = "Issuer does not match the next certificate CN. Chain order is probably wrong.";
              }
            }
          }
        }
      } 
      // chain validation
      file_put_contents('/tmp/verify_cert.' . $random_blurp . '.pem', implode("\n", array_reverse($certificate_chain)).PHP_EOL , FILE_APPEND);
      $verify_output = 0;
      $verify_exit_code = 0;
      $verify_exec = exec(escapeshellcmd('openssl verify -verbose -purpose any -CAfile ' . getcwd() . '/cacert.pem /tmp/verify_cert.' . $random_blurp . '.pem') . "| grep -v OK", $verify_output, $verify_exit_code);

      if ($verify_exit_code != 1) {
        $result["validation"]["status"] = "failed";
        $result["validation"]["error"] = "Error: Validating certificate chain failed: " . str_replace('/tmp/verify_cert.' . $random_blurp . '.pem: ', '', implode("\n", $verify_output));
        $result["warning"][] = "Validating certificate chain failed. Probably non-trusted root/self signed certificate, or the chain order is wrong.";
      } else {
        $result["validation"]["status"] = "success";
      }
      unlink('/tmp/verify_cert.' . $random_blurp . '.pem');
    }

    //chain construction
    if (isset($chain_data) && $factcheck == 0 && $result["validation"]["status"] == "failed") {
      $return_chain = array();
      $export_pem = "";
      openssl_x509_export($chain_data[0], $export_pem);
      $crt_cn = openssl_x509_parse($chain_data[0])['name'];
      $export_pem = "#start " . $crt_cn . "\n" . $export_pem . "\n#end " . $crt_cn . "\n";
      array_push($return_chain, $export_pem);
      $chain_length = count($chain_data);
      $certificate_chain = array();
      if ($chain_length <= $max_chain_length) {
        $issuer_crt = get_issuer_chain($chain_data[0]);
        if (count($issuer_crt['certs']) >= 1) {
          $issuercrts = array_unique($issuer_crt['certs']);
          foreach ($issuercrts as $key => $value) {
            array_push($return_chain, $value);
          }
        }
      }
    }
    if(is_array($return_chain)) {
      $return_chain = array_unique($return_chain);
    }
    if(count($return_chain) > 1) {
      $result["validation"]["cns"] = array();
      $result["correct_chain"]["cns"] = array();
      $crt_cn = array();
      foreach ($return_chain as $retc_key => $retc_value) {
        $issuer_full = "";
        $subject_full = "";
        $sort_issuer = openssl_x509_parse($retc_value)['issuer'];
        $sort_subject = openssl_x509_parse($retc_value)['subject'];
        asort($sort_subject);
        foreach ($sort_subject as $sub_key => $sub_value) {
          $subject_full = "/" . $sub_key . "=" . $sub_value . $subject_full;
        }
        asort($sort_issuer);
        foreach ($sort_issuer as $iss_key => $iss_value) {
          $issuer_full = "/" . $iss_key . "=" . $iss_value . $issuer_full;
        }
        $crt_cn['cn'] = $subject_full;
        $crt_cn['issuer'] = $issuer_full;
        array_push($result["validation"]["cns"], $crt_cn);
      }
      $result["validation"]["correct_chain"] = $return_chain;
    }
    // hostname ip port
    $result["ip"] = $ip;
    if (filter_var(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 )) {
      $addr = inet_pton(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip));
      $unpack = unpack('H*hex', $addr);
      $hex = $unpack['hex'];
      $arpa = implode('.', array_reverse(str_split($hex))) . '.ip6.arpa';
      if (!empty(dns_get_record($arpa, DNS_PTR)[0]["target"])) {
        $result["hostname"] = dns_get_record($arpa, DNS_PTR)[0]["target"];
      } else {
        $result["hostname"] = "$host (No PTR available).";
      }
    } elseif (filter_var(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 )) {
      if (!empty(gethostbyaddr(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip)))) {
        $result["hostname"] = gethostbyaddr(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip));
      } else {
        $result["hostname"] = "$host (No PTR available).";
      }
    } else {
      $result["hostname"] = "$host (No PTR available).";
    }
    $result["port"] = $port;

    if($fastcheck == 0) {
      //heartbleed
      $result['heartbleed'] = test_heartbleed($ip, $port);
      if ($result['heartbleed'] == "vulnerable") {
        $result["warning"][] = 'Vulnerable to the Heartbleed bug. Please update your OpenSSL ASAP!';
      }

      // compression
      $compression = conn_compression($host, $ip, $port);
      if ($compression == false) { 
        $result["compression"] = false;
      } else {
        if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
          // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
          $result["warning"][] = 'SSL compression not tested because of <a href="https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest">bugs</a> in the OpenSSL tools and IPv6.';
        } else {
          $result["compression"] = true;
          $result["warning"][] = 'SSL compression enabled. Please disable to prevent attacks like CRIME.';
        }
        
      }

      // protocols
      $result["protocols"] = array_reverse(ssl_conn_protocols($host, $ip, $port));
      foreach ($result["protocols"] as $key => $value) {
        if ( $value == true ) {
          if ( $key == "sslv2") {
            $result["warning"][] = 'SSLv2 supported. Please disable ASAP and upgrade to a newer protocol like TLSv1.2.';
          }
          if ( $key == "sslv3") {
            $result["warning"][] = 'SSLv3 supported. Please disable and upgrade to a newer protocol like TLSv1.2.';
          }
        } else {
          if ( $key == "tlsv1.2") {
            $result["warning"][] = 'TLSv1.2 unsupported. Please enable TLSv1.2.';
          }
        }
      }

      // ciphersuites
        $ciphersuites_to_test = array('ECDHE-RSA-AES256-GCM-SHA384',
          'ECDHE-ECDSA-AES256-GCM-SHA384',
          'ECDHE-RSA-AES256-SHA384',
          'ECDHE-ECDSA-AES256-SHA384',
          'ECDHE-RSA-AES256-SHA',
          'ECDHE-ECDSA-AES256-SHA',
          'SRP-DSS-AES-256-CBC-SHA',
          'SRP-RSA-AES-256-CBC-SHA',
          'SRP-AES-256-CBC-SHA',
          'DH-DSS-AES256-GCM-SHA384',
          'DHE-DSS-AES256-GCM-SHA384',
          'DH-RSA-AES256-GCM-SHA384',
          'DHE-RSA-AES256-GCM-SHA384',
          'DHE-RSA-AES256-SHA256',
          'DHE-DSS-AES256-SHA256',
          'DH-RSA-AES256-SHA256',
          'DH-DSS-AES256-SHA256',
          'DHE-RSA-AES256-SHA',
          'DHE-DSS-AES256-SHA',
          'DH-RSA-AES256-SHA',
          'DH-DSS-AES256-SHA',
          'DHE-RSA-CAMELLIA256-SHA',
          'DHE-DSS-CAMELLIA256-SHA',
          'DH-RSA-CAMELLIA256-SHA',
          'DH-DSS-CAMELLIA256-SHA',
          'ECDH-RSA-AES256-GCM-SHA384',
          'ECDH-ECDSA-AES256-GCM-SHA384',
          'ECDH-RSA-AES256-SHA384',
          'ECDH-ECDSA-AES256-SHA384',
          'ECDH-RSA-AES256-SHA',
          'ECDH-ECDSA-AES256-SHA',
          'AES256-GCM-SHA384',
          'AES256-SHA256',
          'AES256-SHA',
          'CAMELLIA256-SHA',
          'PSK-AES256-CBC-SHA',
          'ECDHE-RSA-AES128-GCM-SHA256',
          'ECDHE-ECDSA-AES128-GCM-SHA256',
          'ECDHE-RSA-AES128-SHA256',
          'ECDHE-ECDSA-AES128-SHA256',
          'ECDHE-RSA-AES128-SHA',
          'ECDHE-ECDSA-AES128-SHA',
          'SRP-DSS-AES-128-CBC-SHA',
          'SRP-RSA-AES-128-CBC-SHA',
          'SRP-AES-128-CBC-SHA',
          'DH-DSS-AES128-GCM-SHA256',
          'DHE-DSS-AES128-GCM-SHA256',
          'DH-RSA-AES128-GCM-SHA256',
          'DHE-RSA-AES128-GCM-SHA256',
          'DHE-RSA-AES128-SHA256',
          'DHE-DSS-AES128-SHA256',
          'DH-RSA-AES128-SHA256',
          'DH-DSS-AES128-SHA256',
          'DHE-RSA-AES128-SHA',
          'DHE-DSS-AES128-SHA',
          'DH-RSA-AES128-SHA',
          'DH-DSS-AES128-SHA',
          'DHE-RSA-SEED-SHA',
          'DHE-DSS-SEED-SHA',
          'DH-RSA-SEED-SHA',
          'DH-DSS-SEED-SHA',
          'DHE-RSA-CAMELLIA128-SHA',
          'DHE-DSS-CAMELLIA128-SHA',
          'DH-RSA-CAMELLIA128-SHA',
          'DH-DSS-CAMELLIA128-SHA',
          'ECDH-RSA-AES128-GCM-SHA256',
          'ECDH-ECDSA-AES128-GCM-SHA256',
          'ECDH-RSA-AES128-SHA256',
          'ECDH-ECDSA-AES128-SHA256',
          'ECDH-RSA-AES128-SHA',
          'ECDH-ECDSA-AES128-SHA',
          'AES128-GCM-SHA256',
          'AES128-SHA256',
          'AES128-SHA',
          'SEED-SHA',
          'CAMELLIA128-SHA',
          'IDEA-CBC-SHA',
          'PSK-AES128-CBC-SHA',
          'ECDHE-RSA-RC4-SHA',
          'ECDHE-ECDSA-RC4-SHA',
          'ECDH-RSA-RC4-SHA',
          'ECDH-ECDSA-RC4-SHA',
          'RC4-SHA',
          'RC4-MD5',
          'PSK-RC4-SHA',
          'ECDHE-RSA-DES-CBC3-SHA',
          'ECDHE-ECDSA-DES-CBC3-SHA',
          'SRP-DSS-3DES-EDE-CBC-SHA',
          'SRP-RSA-3DES-EDE-CBC-SHA',
          'SRP-3DES-EDE-CBC-SHA',
          'EDH-RSA-DES-CBC3-SHA',
          'EDH-DSS-DES-CBC3-SHA',
          'DH-RSA-DES-CBC3-SHA',
          'DH-DSS-DES-CBC3-SHA',
          'ECDH-RSA-DES-CBC3-SHA',
          'ECDH-ECDSA-DES-CBC3-SHA',
          'DES-CBC3-SHA',
          'PSK-3DES-EDE-CBC-SHA',
          'EDH-RSA-DES-CBC-SHA',
          'EDH-DSS-DES-CBC-SHA',
          'DH-RSA-DES-CBC-SHA',
          'DH-DSS-DES-CBC-SHA',
          'DES-CBC-SHA',
          'EXP-EDH-RSA-DES-CBC-SHA',
          'EXP-EDH-DSS-DES-CBC-SHA',
          'EXP-DH-RSA-DES-CBC-SHA',
          'EXP-DH-DSS-DES-CBC-SHA',
          'EXP-DES-CBC-SHA',
          'EXP-RC2-CBC-MD5',
          'EXP-RC4-MD5',
          'ECDHE-RSA-NULL-SHA',
          'ECDHE-ECDSA-NULL-SHA',
          'AECDH-NULL-SHA',
          'ECDH-RSA-NULL-SHA',
          'ECDH-ECDSA-NULL-SHA',
          'NULL-SHA256',
          'NULL-SHA',
          'NULL-MD5');
        $tested_ciphersuites = ssl_conn_ciphersuites($host, $ip, $port, $ciphersuites_to_test);
        $result["supported_ciphersuites"] = array();
        foreach ($tested_ciphersuites as $key => $value) {
          if ($value == true) {
            $result["supported_ciphersuites"][] = $key;
          }
        }
        
      // tls_fallback_scsv
      $fallback = tls_fallback_scsv($host, $ip, $port);
      if ($fallback['protocol_count'] == 1) {
        $result["tls_fallback_scsv"] = "Only 1 protocol enabled, fallback not possible, TLS_FALLBACK_SCSV not required.";
      } else {
        if ($fallback['tls_fallback_scsv_support'] == 1) {
          $result["tls_fallback_scsv"] = "supported";
        } else {
          if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
          // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
          $result["warning"][] = 'TLS_FALLBACK_SCSV not tested because of <a href="https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest">bugs</a> in the OpenSSL tools and IPv6.';
          } else {
            $result["tls_fallback_scsv"] = "unsupported";
            $result["warning"][] = "TLS_FALLBACK_SCSV unsupported. Please upgrade OpenSSL to enable. This offers downgrade attack protection.";
          }
        }
      }
      //hsts
      $headers = server_http_headers($host, $ip, $port);
      if ($headers["strict-transport-security"]) {
        if ( is_array($headers["strict-transport-security"])) {
        $result["strict_sransport-security"] = substr($headers["strict-transport-security"][0], 0, 50);
        } else {
          $result["strict_transport_security"] = substr($headers["strict-transport-security"], 0, 50);
        }
      } else {
        $result["strict_transport_security"] = 'not set';
        $result["warning"][] = "HTTP Strict Transport Security not set.";
      }
      //hpkp
      if ( $headers["public-key-pins"] ) {
        if ( is_array($headers["public-key-pins"])) {
          $result["public_key_pins"] = substr($headers["public-key-pins"][0], 0, 255);
        } else {
          $result["public_key_pins"] = substr($headers["public-key-pins"], 0, 255);
        }
      } else {
        $result["public_key_pins"] = 'not set';
      }
      if ( $headers["public-key-pins-report-only"] ) {
        if ( is_array($headers["public-key-pins-report-only"])) {
          $result["public_key_pins_report_only"] = substr($headers["public-key-pins-report-only"][0], 0, 255);
        } else {
          $result["public_key_pins_report_only"] = substr($headers["public-key-pins-report-only"], 0, 255);
        }
      } 
      // ocsp stapling
      $stapling = ocsp_stapling($host, $ip, $port);
      if($stapling["working"] == 1) {
        $result["ocsp_stapling"] = $stapling;
      } else {
        if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
          // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
          $result["warning"][] = 'OCSP Stapling not tested because of <a href="https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest">bugs</a> in the OpenSSL tools and IPv6.';
        } else {
          $result["ocsp_stapling"] = "not set";
          $result["warning"][] = "OCSP Stapling not enabled.";
        }
      }
      
      $result["heartbeat"] = heartbeat_test($host, $port);
    }
    $result["openssl_version"] = shell_exec("openssl version");
    $result["datetime_rfc2822"] = shell_exec("date --rfc-2822");
  } 
  return $result;
}






?>
