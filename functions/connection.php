<?php
// Copyright (C) 2015 Remy van Elst

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

function fixed_gethostbyname($host) {
    $ip = gethostbyname($host);
    if ($ip != $host) { 
        return $ip; 
    } else {
        return false;
    }
}

function get(&$var, $default=null) {
    return isset($var) ? $var : $default;
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

function ssl_conn_ciphersuites($host, $port, $ciphersuites){
        $old_error_reporting = error_reporting();
        error_reporting($old_error_reporting ^ E_WARNING); 
        $results = array();
        foreach ($ciphersuites as $value) {
          $results[$value] = false;
          $stream = stream_context_create (array("ssl" => 
          array("verify_peer" => false,
            "verify_peer_name" => false,
            "allow_self_signed" => true,
            'ciphers' => $value,
            "sni_enabled" => true)));
          $read_stream = stream_socket_client("ssl://$host:$port", $errno, $errstr, 2, STREAM_CLIENT_CONNECT, $stream);
          if ( $read_stream === false ) {
            $results[$value] = false;
          } else {
            $results[$value] = true;
          }
        }
        error_reporting($old_error_reporting);
        return $results;
      }

      function ssl_conn_protocols($host, $port){
        $old_error_reporting = error_reporting();
        error_reporting($old_error_reporting ^ E_WARNING); 
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
        error_reporting($old_error_reporting);
        return $results;
      }


function ssl_conn_metadata($host, $port, $chain=null) {
  global $random_blurp;
  global $current_folder;
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
    <section id="conndata">
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
            $chain_length = count($chain);
            $certificate_chain = array();
            if ($chain_length <= 10) {
              for ($i = 0; $i < $chain_length; $i++) {
                if (openssl_x509_parse($chain[$i])['issuer']['CN'] && openssl_x509_parse($chain[$i])['subject']['CN']) {
                  echo "Name...........: <i>";
                  echo htmlspecialchars(openssl_x509_parse($chain[$i])['subject']['CN']);
                  echo " </i><br>Issued by......:<i> ";
                  echo htmlspecialchars(openssl_x509_parse($chain[$i])['issuer']['CN']);
                  echo "</i><br>";

                  $export_pem = "";
                  openssl_x509_export($chain[$i], $export_pem);
                  array_push($certificate_chain, $export_pem);

                  if (openssl_x509_parse($chain[$i])['issuer']['CN'] == openssl_x509_parse($chain[$i + 1])['subject']['CN']){
                    continue;
                  } else {
                    if ($i != $chain_length - 1) {
                      echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>Error: Issuer does not match the next certificate CN. Chain order is probaby wrong.</span><br><br>";
                    }
                  }
                }
              }
              echo "<br>";
            } else {
              echo "<span class='text-danger'>Error: Certificate chain to large.</span><br>";
            }

            file_put_contents('/tmp/verify_cert.' . $random_blurp . '.pem', implode("\n", array_reverse($certificate_chain)).PHP_EOL , FILE_APPEND);

            $verify_output = 0;
            $verify_exit_code = 0;
            $verify_exec = exec(escapeshellcmd('openssl verify -verbose -purpose any -CAfile ' . getcwd() . '/cacert.pem /tmp/verify_cert.' . $random_blurp . '.pem') . "| grep -v OK", $verify_output, $verify_exit_code);

            if ($verify_exit_code != 1) {
              echo "<span class='text-danger glyphicon glyphicon-remove'></span> - <span class='text-danger'>Error: Validating certificate chain failed:</span><br>";
              echo "<pre>";
              echo str_replace('/tmp/verify_cert.' . $random_blurp . '.pem: ', '', implode("\n", $verify_output));
              echo "</pre>";
            } else {
              echo "<span class='text-success glyphicon glyphicon-ok'></span> - <span class='text-success'>Sucessfully validated certificate chain.</span><br>";
            }

            unlink('/tmp/verify_cert.' . $random_blurp . '.pem');

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
        <?php
          if ($_GET['ciphersuites'] == 1) {
        ?>
        <tr>
          <td>Ciphersuites supported by server</td>
          <td>
            <?php
              $ciphersuites_to_test = array('ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES256-SHA384',
                'ECDHE-ECDSA-AES256-SHA384',
    'TLS_FALLBACK_SCSV',
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
              $supported_ciphersuites = ssl_conn_ciphersuites($host, $port, $ciphersuites_to_test);
  
              foreach ($supported_ciphersuites as $key => $value) {
                if($value == true){
                  if (in_array($key, $bad_ciphersuites)) {
                    $bad_ciphersuite = 1;
                    echo "";
                    echo "<span class='text-danger glyphicon glyphicon-remove'></span> ";
                  } else {
                    echo "<span class='glyphicon glyphicon-minus'></span> ";
                  }
                  echo htmlspecialchars($key);
                  echo "<br>";
                } else {
                  echo "<!-- ";
                  echo "<span class='glyphicon glyphicon-remove'></span> - ";
                  echo htmlspecialchars($key);
                  echo " <br -->";
                }
              }
            if ($bad_ciphersuite) {
                ?>
                <p><br>Ciphersuites containing <a href="https://en.wikipedia.org/wiki/Null_cipher">NULL</a>, <a href="https://en.wikipedia.org/wiki/Export_of_cryptography_from_the_United_States">EXP(ort)</a>, <a href="https://en.wikipedia.org/wiki/Weak_key">DES and RC4</a> are marked RED because they are suboptimal.</p>
                <?php               
              }
               
            ?>
          </td>
        </tr>
        <?php
          } else {
        ?>
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
        }
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
    </section>
    <?php
  } else {
    return false;
  }
}
}








?>
