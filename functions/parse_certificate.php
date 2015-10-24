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


function get_sans_from_csr($csr) {
  global $random_blurp;
  global $timeout;
  //openssl_csr_get_subject doesn't support SAN names.
  $filename = "/tmp/csr-" . $random_blurp . "-" . gen_uuid() . ".csr.pem";
  $write_csr = file_put_contents($filename, $csr);
  if($write_csr !== FALSE) {
    $openssl_csr_output = trim(shell_exec("timeout " . $timeout . " openssl req -noout -text -in " . $filename . " | grep -e 'DNS:' -e 'IP:'"));
  }
  unlink($filename);
  if($openssl_csr_output) {
    $sans = array();
    $csr_san_dns = explode("DNS:", $openssl_csr_output);
    $csr_san_ip = explode("IP:", $openssl_csr_output);
    if(count($csr_san_dns) > 1) {
      foreach ($csr_san_dns as $key => $value) {
        if($value) {
          $san = trim(str_replace(",", "", str_replace("DNS:", "", $value)));
          array_push($sans, $san);
        }
      }
    }
    if(count($csr_san_ip) > 1) {
      foreach ($csr_san_ip as $key => $value) {
        if($value) {
          $san = trim(str_replace(",", "", str_replace("IP:", "", $value)));
          array_push($sans, $san);
        }
      }
    } 
  }
  if(count($sans) >= 1) {
    return $sans;
  }
}

function csr_parse($data) {
  //parses the json data from csr_parse_json() to a nice html page.
  echo "<table class='table table-striped table-bordered'>";
  echo "<tr>";
  echo "<td colspan='2'><strong>Certificate Signing Request Data</strong></td>";
  echo "</tr>";
  foreach ($data['subject'] as $key => $value) {
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
      echo ' <img src="'.htmlspecialchars($current_folder) . 'img/blank.gif" class="flag flag-';
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

  if($data['csr_sans']) {
      echo "<tr><td>Subject Alternative Names</td><td><ul>";
      foreach ($data['csr_sans'] as $key => $value) {
        echo "<span style='font-family:monospace;'><li>";
        echo htmlspecialchars($value);
        echo "</li>";
      }
      echo "</ul></td></tr>";
  }

  echo "<tr><td>Public Key PEM (";
  echo htmlspecialchars($data['details']['bits']);
  if ($data['details']['rsa']) {
    echo " RSA";
  }
  if ($data['details']['dsa']) {
    echo " DSA";
  }
  if ($data['details']['dh']) {
    echo " DH";
  }
  if ($data['details']['ec']) {
    echo " ECDSA";
  }
  echo ")</td><td><pre>";
  echo htmlspecialchars($data['details']['key']);
  echo "</pre></td></tr>";

  echo "<tr><td>CSR PEM</td><td><pre>";
  echo htmlspecialchars($data['csr_pem']);
  echo "</pre></td></tr>";
  echo "</table>";
}


function cert_parse($data) {
  //parses the json data from cert_parse_json() to a nice html page.
  //does output formatting based on some parts, like red if cert expired.
  if (is_array($data["warning"]) && count($data["warning"]) >= 1) {
    $data["warning"] = array_unique($data["warning"]);
    if (count($data["warning"]) == 1) {
      echo "<h3>" . count($data["warning"]) . " warning!</h3>";
    } else {
      echo "<h3>" . count($data["warning"]) . " warnings!</h3>";
    }
    foreach ($data["warning"] as $key => $value) {
      echo "<div class='alert alert-danger' role='alert'>";
      echo htmlspecialchars($value);
      echo "</div>";
    }
  }
  echo "<table class='table table-striped table-bordered'>";
  echo "<tr>";
  echo "<td colspan='2'><strong>Certificate Data</strong></td>";
  echo "</tr>";
  $today = date("Y-m-d");
  echo "<tr><td colspan='2'>\n";
  echo "<table class='table'>\n";
  echo "<thead><tr>\n";
  echo "<th>Hostname</th>\n";
  echo "<th>Not Expired</th>\n";
  echo "<th>Issuer</th>\n";
  echo "<th>CRL</th>\n";
  echo "<th>OCSP</th>\n";
  echo "<th>Signing Type</th>\n";
  echo "</tr>\n</thead>\n<tbody>\n<tr>";
  // hostname validation
  if ($data["hostname_in_san_or_cn"] == "true") {
    echo '<td><h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1></td>';
  } elseif ($data["hostname_in_san_or_cn"] == "false")  {
    echo '<td><h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1></td>';
  } elseif ($data["hostname_in_san_or_cn"] == "n/a; ca signing certificate")  {
    echo "<td></td>";
  } else {
    echo "<td><h1><span class='text-danger glyphicon glyphicon-question-sign'></span>&nbsp;</h1></td>";
  }
  // expired
  if ( $today > date(DATE_RFC2822,$data['cert_data']['validFrom_time_t']) || strtotime($today) < strtotime(date(DATE_RFC2822,$data['cert_data']['validTo_time_t'])) ) {
    echo '<td><h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1></td>';
  } else {
    echo '<td><h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1></td>';
  }
  // issuer
  if (!empty($data["issuer_valid"])) {
    if ($data["issuer_valid"] == true) {
      echo '<td><h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1></td>';
    } else {
      echo '<td><h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1></td>';
    }
  } else {
    echo '<td> </td>';
  }
  // crl
  if ( !empty($data['crl'][1]['status']) ) {
    if ($data['crl'][1]['status'] == "ok") {
      echo "<td><h1><span class='text-success glyphicon glyphicon-ok'></span>&nbsp;</h1></td>";
    } else {
      echo '<td><h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1></td>';
    }
  } else {
    echo '<td> </td>';
  }
  // ocsp
  if (!empty($data['ocsp'][1]['ocsp_uri'])) {
    echo "<td>";
    if ($data['ocsp'][1]["status"] == "good") { 
      echo '<h1><span class="text-success glyphicon glyphicon-ok"></span>&nbsp;</h1>';
    } else if ($data['ocsp'][1]["status"] == "revoked") {
      echo '<h1><span class="text-danger glyphicon glyphicon-remove"></span>&nbsp;</h1>';
    } else {
      echo '<h1><span class="text-danger glyphicon glyphicon-question-sign"></span>&nbsp;</h1>';
    }
    echo "</td>";
  } else {
    echo "<td> </td>";
  }
  // self signed/ca/ca root
  if (strpos($data['cert_data']['extensions']['basicConstraints'], "CA:TRUE") !== false && $data['cert_data']['issuer']['CN'] == $data['cert_data']['subject']['CN'] ) {
    echo '<td><span class="text-success">CA Root Certificate</span></td>';
  } else if (strpos($data['cert_data']['extensions']['basicConstraints'], "CA:TRUE") !== false) {
    echo '<td><span class="text-success">CA Certificate</span></td>';
  } else if ($data['cert_data']['issuer']['CN'] == $data['cert_data']['subject']['CN']) {
    echo '<td><span class="text-danger">Self Signed</span></td>';
  } else {
    echo "<td>Signed by CA</td>";
  }
  echo "</tr>";
  echo "</tbody></table>";
  echo "</td></tr>";
  if (!empty($data['cert_data']['subject']) ) {
    foreach ($data['cert_data']['subject'] as $key => $value) {
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
        echo ' <img src="'.htmlspecialchars($current_folder) . 'img/blank.gif" class="flag flag-';
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
      echo "</td>";
      echo "</tr>";
    }
  }
  // san
  if (!empty($data['cert_data']['extensions']['subjectAltName'])) {
  echo "<tr>";
  echo "<td>Subject Alternative Names</td>";
  echo "<td>";
  foreach ( explode("DNS:", $data['cert_data']['extensions']['subjectAltName']) as $altName ) {
    if ( !empty(str_replace(',', " ", "$altName"))) {
      echo "<span style='font-family:monospace;'>";
      echo htmlspecialchars(str_replace(',', " ", "$altName"));
      echo "</span><br>";
    }
  } 
  echo "</td>";
  echo "</tr>";
  }
  // validation type
  echo "<tr>";
  echo "<td>Type</td>";
  echo "<td>";
  if ($data["validation_type"] == "extended") {
    echo '<span class="text-success">Extended Validation</span>';
  } elseif ($data["validation_type"] == "organization") {
    echo "Organization Validation";
  } elseif ($data["validation_type"] == "domain") {
    echo "Domain Validation";
  }
  // full subject
  echo "</td>";
  echo "</tr>";
  echo "<tr>";
  echo "<td>Full Subject</td>";
  echo "<td><span style='font-family:monospace;'>";
  echo htmlspecialchars($data['cert_data']['name']);
  echo "</span></td>";
  echo "</tr>";
  echo "<tr>";
  echo "<td colspan='2'><strong>Issuer</strong></td>";
  echo "</tr>";
  if (!empty($data['cert_data']['issuer']) ) {
    foreach ($data['cert_data']['issuer'] as $key => $value) {
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
        echo ' <img src="'.htmlspecialchars($current_folder) . 'img/blank.gif" class="flag flag-';
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
      echo "</td>";
      echo "</tr>";
    }
  }
  // valid from 
  echo "<tr>";
  echo "<td colspan='2'><strong>Validity</strong></td>";
  echo "</tr>";
  if ( !empty($data['cert_data']['validFrom_time_t']) ) { 
    echo "<tr>";
    echo "<td>Valid From</td>";
    echo "<td>";
    if ( $today < date(DATE_RFC2822,$data['cert_data']['validFrom_time_t']) ) {
      echo '<span class="text-success glyphicon glyphicon-ok-sign"></span>';
      echo '<span class="text-success"> - ';
    } else {
      echo '<span class="text-danger glyphicon glyphicon-exclamation-sign"></span>';
      echo '<span class="text-danger"> - ';
    }
    echo htmlspecialchars(date(DATE_RFC2822,$data['cert_data']['validFrom_time_t'])); 
    echo "</span>";
    echo "</td>";
    echo "</tr>";
  }
  // issued to expired
  if ( !empty($data['cert_data']['validTo_time_t']) ) { 
    echo "<tr>";
    echo "<td>Valid Until</td>";
    echo "<td>";
    if ( strtotime($today) < strtotime(date(DATE_RFC2822,$data['cert_data']['validTo_time_t'])) ) {
      echo '<span class="text-success glyphicon glyphicon-ok-sign"></span>';
      echo '<span class="text-success"> - ';
    } else {
      echo '<span class="text-danger glyphicon glyphicon-exclamation-sign"></span>';
      echo '<span class="text-danger"> - ';
    }
    echo htmlspecialchars(date(DATE_RFC2822,$data['cert_data']['validTo_time_t'])); 
    echo "</span>";
    echo "</td>";
    echo "</tr>";
  };
  if ( is_array($data['crl']) ) {
    echo "<tr>";
    echo "<td>CRL</td>";
    echo "<td>";
    foreach ($data['crl'] as $key => $value) {
      if ($value) {
        if ($value["status"] == "ok") {
          echo "<span class='text-success glyphicon glyphicon-ok-sign'></span>";
          echo "<span class='text-success'> - Not on CRL: " . htmlspecialchars($value["crl_uri"]) . "</span><br>";
          echo "Last update: " . htmlspecialchars($value['crl_last_update']) . "<br>\n";
          echo "Next update: " . htmlspecialchars($value['crl_next_update']) . "<br>\n";
        } elseif ($value["status"] == "revoked") {
          echo "<span class='text-danger glyphicon glyphicon-exclamation-sign'></span>";
          echo "<span class='text-danger'> - Revoked on CRL: " . htmlspecialchars($value["crl_uri"]) . "</span><br>\n";
          echo "<span class='text-danger'>Revocation date: " . htmlspecialchars($value["revoked_on"]) . "</span><br>\n";
          echo "<br>Last update: " . htmlspecialchars($value['crl_last_update']) . "<br>\n";
          echo "Next update: " . htmlspecialchars($value['crl_next_update']) . "<br>\n";
        } else {
          echo "<span class='text-danger glyphicon glyphicon-exclamation-sign'></span>";
          echo "<span class='text-danger'> - CRL invalid: (" . htmlspecialchars($value["crl_uri"]) . ")</span><br>";
          echo "<pre> " . htmlspecialchars($value["error"]) . "</pre>";
        }
      }
      if (count($data['ocsp']) > 1) {
        echo "<hr>";
      }
    }
    echo "</td>";
    echo "</tr>";
  } else {
    echo "<tr><td>CRL</td><td>No CRL URI found in certificate</td></tr>";
  }
  // ocsp
  if ( is_array($data['ocsp'])) { 
    echo "<tr>";
    echo "<td>OCSP</td>";
    echo "<td>";
    foreach ($data['ocsp'] as $key => $value) {
      if ($value) {
        if ($value["status"] == "good") { 
          echo '<span class="text-success glyphicon glyphicon-ok-sign"></span> ';
          echo '<span class="text-success"> - OK: ';
          echo htmlspecialchars($value['ocsp_uri']);
          echo "</span><br>";
          echo "Last update: " . htmlspecialchars($value["this_update"]) . "<br>\n";
          echo "Next update: " . htmlspecialchars($value["next_update"]) . "<br>\n";
        } else if ( $value["status"] == "revoked") {
          echo '<span class="text-danger glyphicon glyphicon-remove-sign"></span>';
          echo '<span class="text-danger"> - REVOKED: ';
          echo htmlspecialchars($value['ocsp_uri']);
          echo "</span><br>";
          echo "<span class='text-danger'>Revocation Time: " . htmlspecialchars($value["revocation_time"]) . "<br>\n";
          echo "Revocation Reason: " . htmlspecialchars($value["reason"]). "</span><br>";
          echo "<br>Last update: " . htmlspecialchars($value["this_update"]) . "<br>\n";
          echo "Next update: " . htmlspecialchars($value["next_update"]) . "<br>\n";
        } else {
          echo '<span class="text-danger glyphicon glyphicon-question-sign"></span>';
          echo '<span class="text-danger"> - UNKNOWN: ';
          echo " - " . htmlspecialchars($value['ocsp_uri']) . "</span><br>";
          echo "<pre>" . htmlspecialchars($value["error"]) . "</pre>";
        }
      }
      if (count($data['ocsp']) > 1) {
        echo "<hr>";
      }
    }
  } else {
    if ($data["ocsp"] == "No issuer cert provided. Unable to send OCSP request.") {
      echo "<tr><td>OCSP</td><td>No issuer certificate provided. Unable to send OCSP request.</td></tr>";
    } else {
      echo "<tr><td>OCSP</td><td>No OCSP URI found in certificate</td></tr>";
    }
  }
  if(!empty($_GET['host'])) {
    echo "<tr>";
    echo "<td>Hostname Validation</td>";
    echo "<td>";
    // hostname validation
    if ($data["hostname_in_san_or_cn"] == "true") {
      echo "<span class='text-success glyphicon glyphicon-ok'></span>\n<span class='text-success'> - ";
      echo htmlspecialchars($data['hostname_checked']);
      echo " found in CN or SAN.</span>";
    } elseif ($data["hostname_in_san_or_cn"] == "false")  {
      echo '<span class="text-danger glyphicon glyphicon-remove"></span><span class="text-danger"> - ';
      echo htmlspecialchars($data['hostname_checked']); 
      echo ' NOT found in CN or SAN.</span>';
    } elseif ($data["hostname_in_san_or_cn"] == "n/a; ca signing certificate")  {
      echo "Not applicable, this seems to be a CA signing certificate.";
    } else {
      echo "Not applicable, this seems to be a CA signing certificate.";
    }
    echo "</td>";
    echo "</tr>";
  }
  // details
  echo "<tr>";
  echo "<td colspan='2'><strong>Details</strong></td>";
  echo "</tr>";
  if ( !empty($data['cert_data']['purposes']) ) { 
    echo "<tr>";
    echo "<td>Purposes</td>";
    echo "<td>";
    foreach ($data['cert_data']['purposes'] as $key => $purpose) {
      if ($purpose["general"]) {
        echo htmlspecialchars($key);
        echo " ";
      }
    }
    echo "</td>";
    echo "</tr>";
    echo "<tr>";
    echo "<td>Purposes CA</td>";
    echo "<td>";
    foreach ($data['cert_data']['purposes'] as $key => $purpose) {
      if ($purpose["ca"]) {
        echo htmlspecialchars($key);
        echo " ";
      }
    }
    echo "</td>";
    echo "</tr>";
  }
  // serial number
  if (!empty($data['serialNumber']) ) { 
    echo "<tr>";
    echo "<td>Serial</td>";
    echo "<td>";
    echo "<span style='font-family:monospace;'>" . htmlspecialchars($data['serialNumber']) . "</span>";
    echo "</td>";
    echo "</tr>";
  }
  echo "<tr>";
  echo "<td>Key Size / Type</td>";
  echo "<td>";
  // key details
  echo htmlspecialchars($data["key"]['bits']);
  echo " bits ";
  echo htmlspecialchars($data["key"]['type']);
  echo "</td>";
  echo "</tr>";
  echo "<tr>";
  echo "<td>";
  echo "Weak debian key";
  echo "</td>";
  if ($data["key"]["weak_debian_rsa_key"] == 1) {
    echo "<td>";
    echo "<span class='text-danger glyphicon glyphicon-exclamation-sign'></span><span class='text-danger'> - This is a <a href='https://wiki.debian.org/SSLkeys'>weak debian key</a>. Replace it as soon as possible.</span>";
    echo "</td>";
  } else {
    echo "<td>";
    echo "This is not a <a href='https://wiki.debian.org/SSLkeys'>weak debian key</a>.";
    echo "</td>";
  }
  echo "</tr>";
  echo "<tr>";
  echo "<td>Signature Algorithm</td>";
  echo "<td>";
  echo $data["key"]["signature_algorithm"];
  echo "</td>";
  echo "</tr>";

  echo "<tr>";
  echo "<td>Hashes</td>";
  echo "<td>";
    echo "<table class='table table-striped'>";
    foreach ($data["hash"] as $key => $value) {
      echo "<tr><td>";
      echo htmlspecialchars(strtoupper($key));
      echo "</td><td><span style='font-family:monospace;'>";
      echo wordwrap(htmlspecialchars($value), 64, "<br>\n", TRUE);
      echo "</span></td></tr>";
    }
  echo "</table>";
  echo "</td>";
  echo "</tr>";

  if ($_GET['fastcheck'] == 0 && !empty($_GET['host'])) {
    echo "<tr>";
    echo "<td>TLSA DNS </td>";
    echo "<td>";
    if($data['tlsa']['error'] == 'none' && !empty($data['tlsa'])) {
      echo "<table class='table table-striped'>";
      foreach ($data["tlsa"] as $key => $value) {
        switch ($key) {
          case 'tlsa_hash':
            echo "<tr><td>Record Data</td><td>" . htmlspecialchars($value) . "</td></tr>";
            break;
          case 'tlsa_usage':
            echo "<tr><td>Usage</td><td>";
            switch ($value) {
              case '0':
                echo "0: PKIX-TA: Certificate Authority Constraint";
                break;
              case '1':
                echo "1: PKIX-EE: Service Certificate Constraint";
                break;
              case '2':
                echo "2: DANE-TA: Trust Anchor Assertion";
                break;
              case '3':
                echo "3: DANE-EE: Domain Issued Certificate";
                break;
              default:
                echo "<span class='text-danger glyphicon glyphicon-remove'></span><span class='text-danger'> - Incorrect usage parameter: ". htmlspecialchars($value) . "</span>";
                break;
            }
            break;
          case 'tlsa_selector':
            echo "<tr><td>Selector</td><td>";
            switch ($value) {
              case '0':
                echo "0: Cert: Use full certificate";
                break;
              case '1':
                echo "1: SPKI: Use subject public key";
                break;
              default:
                echo "<span class='text-danger glyphicon glyphicon-remove'></span><span class='text-danger'> - Incorrect selector parameter: ". htmlspecialchars($value) . "</span>";
                break;
            }
            break;
          case 'tlsa_matching_type':
            echo "<tr><td>Matching Type</td><td>";
            switch ($value) {
              case '0':
                echo "0: Full: No Hash";
                break;
              case '1':
                echo "1: SHA-256 hash";
                break;
              case '2':
                echo "2: SHA-512 hash";
                break;
              default:
                echo "<span class='text-danger glyphicon glyphicon-remove'></span><span class='text-danger'> - Incorrect matching type parameter: ". htmlspecialchars($value) . "</span>";
                break;
            }
            break;      
          }
      echo "</td></tr>";
      }
      if ($data['tlsa']['tlsa_matching_type'] == "1" || $data['tlsa']['tlsa_matching_type'] == 2) {
        echo "<tr><td>DNS Hash Matches Certificate Hash</td><td>";
        if($data['tlsa']['tlsa_matching_type'] == '1') {
          echo "SHA 256 ";
          if ($data['tlsa']['tlsa_hash'] == $data['hash']['sha256']) {
            echo "<span class='text-success glyphicon glyphicon-ok'></span><span class='text-success'> - Hash match</span>";
          } else {
            echo "<span class='text-danger glyphicon glyphicon-remove'></span><span class='text-danger'> - Hash does not match</span>";
          }
        }
        if($data['tlsa']['tlsa_matching_type'] == '2') {
          echo "SHA 512 ";
          if ($data['tlsa']['tlsa_hash'] == $data['hash']['sha512']) {
            echo "<span class='text-success glyphicon glyphicon-ok'></span><span class='text-success'> Hash match</span>";
          } else {
            echo "<span class='text-danger glyphicon glyphicon-remove'></span><span class='text-danger'> - Hash does not match</span>";
          }
        }
      }
      echo "</table>";
    } else {
      echo "<p>";
      echo htmlspecialchars($data['tlsa']['error']);
      if($data['tlsa']['example']) {
        echo "Here's an example TLSA record based on this certificate's SHA-256 hash: <br><pre>";
        echo htmlspecialchars($data['tlsa']['example']);
        echo "</pre></p>";
      }
    }
    echo "<p>Please note that the DNSSEC chain is not validated. The status of the DNSSEC signature will not show up here.<br><a href='https://wiki.mozilla.org/Security/DNSSEC-TLS-details'>More information about TLSA and DNSSEC.</a> - Simple TLSA record generator <a href='https://www.huque.com/bin/gen_tlsa'>here</a>.";
    echo "</td>";
    echo "</tr>";
  }
  
  if (count($data['cert_data']['extensions']) >= 1) {
    echo "<tr>";
    echo "<td>Extensions</td>";
    echo "<td>";
    ?>
    <div class="panel-group" id="accordion<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" role="tablist" aria-multiselectable="true">
      <div class="panel panel-default">
        <div class="panel-heading" role="tab" id="heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <h4 class="panel-title">
            <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" aria-expanded="false" aria-controls="collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
              Click to Open/Close
            </a>
          </h4>
        </div>
        <div id="collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" class="panel-collapse collapse" role="tabpanel" aria-labelledby="heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <div class="panel-body">
            <?php 
            foreach ($data['cert_data']['extensions'] as $name=>$extension) {

              if ( !empty(str_replace(',', " ", "$extension"))) {
                echo "<strong>" . htmlspecialchars("$name") . "</strong>";
                echo "<pre>";
                echo htmlspecialchars($extension);
                echo "</pre>";
              }
            } 
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</td>";
    echo "</tr>";
  } else {
    echo "<tr>";
    echo "<td>Extensions</td>";
    echo "<td>";
    echo "None";
    echo "</td>";
    echo "</tr>";
  }
  if(!empty($data["key"]["certificate_pem"])) {
    echo "<tr>";
    echo "<td>Certificate PEM </td>";
    echo "<td>";
    ?>
    <div class="panel-group" id="pem-accordion<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" role="tablist" aria-multiselectable="true">
      <div class="panel panel-default">
        <div class="panel-heading" role="tab" id="pem-heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <h4 class="panel-title">
            <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" aria-expanded="false" aria-controls="pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
              Click to Open/Close
            </a>
          </h4>
        </div>
        <div id="pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" class="panel-collapse collapse" role="tabpanel" aria-labelledby="pem-heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <div class="panel-body">
            <?php 
            echo "<pre>";
            echo htmlspecialchars($data["key"]["certificate_pem"]);
    echo "</pre>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</td>";
    echo "</tr>";
  }
            
  if(!empty($data['key']['public_key_pem'])) {
    echo "<tr>";
    echo "<td>Public Key PEM </td>";
    echo "<td>";
    ?>
    <div class="panel-group" id="pub-pem-accordion<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" role="tablist" aria-multiselectable="true">
      <div class="panel panel-default">
        <div class="panel-heading" role="tab" id="pub-pem-heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <h4 class="panel-title">
            <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#pub-pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" aria-expanded="false" aria-controls="pub-pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
              Click to Open/Close
            </a>
          </h4>
        </div>
        <div id="pub-pem-collapse<?php echo bcdechex($data['cert_data']['serialNumber']); ?>" class="panel-collapse collapse" role="tabpanel" aria-labelledby="pub-pem-heading<?php echo bcdechex($data['cert_data']['serialNumber']); ?>">
          <div class="panel-body">
            <?php
              echo "<pre>"; 
              echo htmlspecialchars($data['key']['public_key_pem']);
    echo "</pre>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</div>";
    echo "</td>";
    echo "</tr>";

  // correct chain
  if (is_array($data["correct_chain"]["chain"])) {
    echo "<tr>";
    echo "<td>Certificate Chain</td>";
    echo "<td>";
    echo "<p>We've constructed the certificate chain in the correct order of this certificate based on the '<code>authorityInfoAccess</code>' extension and earlier saved certificates. The result also contains this certificate as the first one.<br>";

    echo "<p>This is our best guess at the correct CA Chain: <br><ul>";
    foreach ($data['correct_chain']['cns'] as $cn_key => $cn_value) {
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
    foreach ($data['correct_chain']['chain'] as $cert) {
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


    echo "<tr>";
    echo "<td><a href='https://raymii.org/s/articles/HTTP_Public_Key_Pinning_Extension_HPKP.html'>SPKI Hash</a></td>";
    echo "<td>";
    print("<span style='font-family:monospace;'>" . htmlspecialchars($data['key']['spki_hash']) . "</span>");
    echo "</td>";
    echo "</tr>";
  }
  echo "</tbody>";
  echo "</table>";
}
    



































function cert_parse_json($raw_cert_data, $raw_next_cert_data=null, $host=null, $validate_hostname=false, $port="443", $include_chain=null) {
  global $random_blurp;
  global $ev_oids;
  global $timeout;
  $result = array();
  $cert_data = openssl_x509_parse($raw_cert_data);
  if (isset($raw_next_cert_data)) {
    $next_cert_data = openssl_x509_parse($raw_next_cert_data);
  }
  $today = date("Y-m-d"); 
  //cert 
  if (isset($cert_data) ) {
    // purposes
    $purposes = array();
    foreach ($cert_data['purposes'] as $key => $purpose) {
      $purposes[$purpose[2]]["ca"] = $purpose[1];
      $purposes[$purpose[2]]["general"] = $purpose[0];
    }
    unset($cert_data['purposes']);
    $cert_data['purposes'] = $purposes;
    $result["cert_data"] = $cert_data;
  }

// valid from 
  if ( !empty($result['cert_data']['validFrom_time_t']) ) { 
    if ( $today < date(DATE_RFC2822,$result['cert_data']['validFrom_time_t']) ) {
      $result['cert_issued_in_future'] = false;
    } else {
      $result['cert_issued_in_future'] = true;
      $result['warning'][] = "Certificate issue date is in the future: " . date(DATE_RFC2822,$data['cert_data']['validFrom_time_t']); 
    }
  }
  // expired
  if (!empty($cert_data['validTo_time_t'])) { 
    if ($today > date(DATE_RFC2822,$cert_data['validFrom_time_t']) || strtotime($today) < strtotime(date(DATE_RFC2822,$cert_data['validTo_time_t']))) {
      $result['cert_expired'] = false;
    } else {
      $result['cert_expired'] = true;
      $result['warning'][] = "Certificate expired! Expiration date: " . date(DATE_RFC2822,$cert_data['validTo_time_t']);
    }
  }
  // almost expired
  if (!empty($cert_data['validTo_time_t'])) {
    $certExpiryDate = strtotime(date(DATE_RFC2822,$cert_data['validTo_time_t']));
    $certExpiryDiff = $certExpiryDate - strtotime($today);
    if ($certExpiryDiff < 2592000) {
      $result['cert_expires_in_less_than_thirty_days'] = true;
      $result['warning'][] = "Certificate expires in " . round($certExpiryDiff / 84600) . " days!. Expiration date: " . date(DATE_RFC2822,$certExpiryDate);
    } else {
      $result['cert_expires_in_less_than_thirty_days'] = false;
    }
  }

  if ( array_search(explode("Policy: ", explode("\n", $cert_data['extensions']['certificatePolicies'])[0])[1], $ev_oids) ) {
    $result["validation_type"] = "extended";
  } else if ( isset($cert_data['subject']['O'] ) ) {
    $result["validation_type"] = "organization";
  } else if ( isset($cert_data['subject']['CN'] ) ) {
    $result["validation_type"] = "domain";
  }
  // issuer
  if ($raw_next_cert_data) {
    if (verify_cert_issuer_by_subject_hash($raw_cert_data, $raw_next_cert_data) ) {
      $result["issuer_valid"] = true; 
    } else {
      $result["issuer_valid"] = false;
      $result['warning'][] = "Provided certificate issuer does not match issuer in certificate. Sent chain order wrong.";
    }
  } 
  // crl
  if (isset($cert_data['extensions']['crlDistributionPoints']) ) {
    $result["crl"] = crl_verify_json($raw_cert_data);
    if (is_array($result["crl"])) {
      foreach ($result["crl"] as $key => $value) {
        if ($value["status"] == "revoked") {
          $result['warning'][] = "Certificate revoked on CRL: " . $value['crl_uri'] . ". Revocation time: " . $value['revoked_on'] . ".";
        }
      }
    }
  } else {
    $result["crl"] = "No CRL URI found in certificate";
  }
  // ocsp
  if (isset($cert_data['extensions']['authorityInfoAccess'])) { 
    $ocsp_uris = explode("OCSP - URI:", $cert_data['extensions']['authorityInfoAccess']);
    unset($ocsp_uris[0]);
    if (isset($ocsp_uris) ) {
      if (isset($raw_next_cert_data)) {
        foreach ($ocsp_uris as $key => $ocsp_uri) {
          $ocsp_uri = explode("\n", $ocsp_uri)[0];
          $ocsp_uri = explode(" ", $ocsp_uri)[0];
          $result["ocsp"]["$key"] = ocsp_verify_json($raw_cert_data, $raw_next_cert_data, $ocsp_uri);
          if ($result['ocsp'][$key]["status"] == "revoked") {
            $result['warning'][] = "Certificate revoked on OCSP: " . $result['ocsp'][$key]['ocsp_uri'] . ". Revocation time: " . $result['ocsp'][$key]['revocation_time'] . ".";
          } elseif ($result['ocsp'][$key]["status"] == "unknown") {
            $result['warning'][] = "OCSP error on: " . $result['ocsp'][$key]['ocsp_uri'] . ".";
          }
        } 
      } else {
        $result["ocsp"] = "No issuer cert provided. Unable to send OCSP request.";
      }
    } else {
        $result["ocsp"] = "No OCSP URI found in certificate";
    }
  } else {
    $result["ocsp"] = "No OCSP URI found in certificate";
  }
  // hostname validation
  if ($validate_hostname == true) {
    $result["hostname_checked"] = $host;
    if (isset($cert_data['subject']['CN'])) {
      if ( verify_certificate_hostname($raw_cert_data, $host) ) {
        $result["hostname_in_san_or_cn"] = "true";
      } else {
        $result["hostname_in_san_or_cn"] = "false";
        $result['warning'][] = "Hostname " . $host . " not found in certificate.";
      }
    }
  } else {
    $result["hostname_in_san_or_cn"] = "n/a; ca signing certificate";
  }
  //serial number
  if ( isset($cert_data['serialNumber']) ) { 
    $serial = [];
    $sn = str_split(strtoupper(bcdechex($cert_data['serialNumber'])), 2);
    $sn_len = count($sn);
    foreach ($sn as $key => $s) {
      $serial[] = htmlspecialchars($s);
      if ( $key != $sn_len - 1) {
        $serial[] = ":";
      }
    }
    $result["serialNumber"] = implode("", $serial);
  }

  // key details
  $key_details = openssl_pkey_get_details(openssl_pkey_get_public($raw_cert_data));
  $export_pem = "";
  openssl_x509_export($raw_cert_data, $export_pem);

  // save pem. this because the reconstruct chain function works better
  // this way. not all certs have authorityinfoaccess. We first check if
  // we already have a matching cert.
  if (!is_dir('crt_hash')) {
    mkdir('crt_hash');
  }
  // filenames of saved certs are hashes of the asort full subject. 
  $sort_subject = $cert_data['subject'];
  asort($sort_subject);
  foreach ($sort_subject as $key => $value) {
    $name_full = "/" . $key . "=" . $value . $name_full;
  }
  $crt_hash = hash("sha256", $name_full);
  $crt_hash_folder = "crt_hash/";
  $crt_hash_file = $crt_hash_folder . $crt_hash . ".pem";
  if(file_exists($crt_hash_file)) {
    if (time()-filemtime($crt_hash_file) > 5 * 84600) {
      // file older than 5 days. crt might have changed, retry.
      $content_hash = sha1_file($crt_hash_file);
      rename($crt_hash_file, $crt_hash_folder . $content_hash . "content_hash_save.pem");
      file_put_contents($crt_hash_file, $export_pem);
    }
  } else {
    file_put_contents($crt_hash_file, $export_pem);
  }
  if(stat($crt_hash_file)['size'] < 10 ) {
    //probably a corrupt file. sould be at least +100KB.
    unlink($crt_hash_file);
  }

  //chain reconstruction
  if($include_chain && $raw_cert_data) {
    $return_chain = array();
    $export_pem = "";
    openssl_x509_export($raw_cert_data, $export_pem);
    $crt_cn = openssl_x509_parse($raw_cert_data)['name'];
    $export_pem = "#start " . $crt_cn . "\n" . $export_pem . "\n#end " . $crt_cn . "\n";
    array_push($return_chain, $export_pem);
    $certificate_chain = array();
    $issuer_crt = get_issuer_chain($raw_cert_data);
    if (count($issuer_crt['certs']) >= 1) {
      $issuercrts = array_unique($issuer_crt['certs']);
      foreach ($issuercrts as $key => $value) {
        array_push($return_chain, $value);
      }
    }
    $return_chain = array_unique($return_chain);
    if(count($return_chain) > 1) {
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
        array_push($result["correct_chain"]["cns"], $crt_cn);
      }
      $result["correct_chain"]["chain"] = $return_chain;
    }
  }

  //hashes
  $string = $export_pem;
  $pattern = '/-----(.*)-----/';
  $replacement = '';
  $string = preg_replace($pattern, $replacement, $string);

  $pattern = '/\n/';
  $replacement = '';
  $export_pem_preg = preg_replace($pattern, $replacement, $string);
  $export_pem_preg = wordwrap($export_pem_preg, 77, "\n", TRUE);
  $result['hash']['md5'] = cert_hash('md5',       $export_pem_preg);
  $result['hash']['sha1'] = cert_hash('sha1',     $export_pem_preg);
  $result['hash']['sha256'] = cert_hash('sha256', $export_pem_preg);
  $result['hash']['sha384'] = cert_hash('sha384', $export_pem_preg);
  $result['hash']['sha512'] = cert_hash('sha512', $export_pem_preg);
  
  //TLSA check
  if (!empty($cert_data['subject']['CN']) && !empty($host)) {
    if ($validate_hostname == true) {
      $tlsa_record = shell_exec("timeout " . $timeout . " dig +short +dnssec +time=" . $timeout . " TLSA _" . escapeshellcmd($port) . "._tcp." . escapeshellcmd($host) . " 2>&1 | head -n 1");
      if (!empty($tlsa_record)) {
        $tlsa = explode(" ", $tlsa_record, 4);
        $pattern = '/ /';
        $replacement = '';
        $result['tlsa']['tlsa_hash'] = trim(strtolower(preg_replace($pattern, $replacement, $tlsa[3])));
        $result['tlsa']['tlsa_usage'] = $tlsa[0];
        $result['tlsa']['tlsa_selector'] = $tlsa[1];
        $result['tlsa']['tlsa_matching_type'] = $tlsa[2];
        $result['tlsa']['error'] = 'none';
      } else {

        $result['tlsa']['error'] = 'No TLSA record found.';
        $result['tlsa']['example'] = '_'. htmlspecialchars($port) . '._tcp.' . htmlspecialchars($host) . ' IN TLSA 3 0 1 ' . $result['hash']['sha256'] . ';';
      }
    } else {
      $result['tlsa']['error'] = 'CA certificate, TLSA not applicable.';
    }
  }
  if (isset($key_details['rsa'])) {
    $result["key"]["type"] = "rsa";
    $result["key"]["bits"] = $key_details['bits'];
    if ($key_details['bits'] < 2048) {
      $result['warning'][] = $key_details['bits'] . " bit RSA key is not safe. Upgrade to at least 4096 bits.";
    }
  
  // weak debian key check
  $bin_modulus = $key_details['rsa']['n'];
  # blacklist format requires sha1sum of output from "openssl x509 -noout -modulus" including the Modulus= and newline.
  # create the blacklist:
  # https://packages.debian.org/source/squeeze/openssl-blacklist
  # svn co svn://svn.debian.org/pkg-openssl/openssl-blacklist/
  # find openssl-blacklist/trunk/blacklists/ -iname "*.db" -exec cat {} >> unsorted_blacklist.db \;
  # sort -u unsorted_blacklist.db > debian_blacklist.db

  $mod_sha1sum = sha1("Modulus=" . strtoupper(bin2hex($bin_modulus)) . "\n");
  $blacklist_file = fopen('inc/debian_blacklist.db', 'r');
  $key_in_blacklist = false;
  while (($buffer = fgets($blacklist_file)) !== false) {
      if (strpos($buffer, $mod_sha1sum) !== false) {
          $key_in_blacklist = true;
          break; 
      }      
    }
    fclose($blacklist_file);
    if ($key_in_blacklist == true) {
      $result["key"]["weak_debian_rsa_key"] = "true";
      $result['warning'][] = "Weak debian key found. Remove this key right now and create a new one.";
    }
  } else if (isset($key_details['dsa'])) {
  $result["key"]["type"] = "dsa";
    $result["key"]["bits"] = $key_details['bits'];
  } else if (isset($key_details['dh'])) {
    $result["key"]["type"] = "dh";
    $result["key"]["bits"] = $key_details['bits'];
  } else if (isset($key_details['ec'])) {
    $result["key"]["type"] = "ecdsa";
    $result["key"]["bits"] = $key_details['bits'];
  } else {
    $result["key"]["type"] = "unknown";
    $result["key"]["bits"] = $key_details['bits'];
  }
  // signature algorithm
  $result["key"]["signature_algorithm"] = cert_signature_algorithm($raw_cert_data);
  if ($result["key"]["signature_algorithm"] == "sha1WithRSAEncryption") {
    $result['warning'][] = "SHA-1 certificate. Upgrade (re-issue) to SHA-256 or better.";
  }
  if(isset($export_pem)) {
    $result["key"]["certificate_pem"] = $export_pem;
  }
  if(isset($key_details['key'])) {
    $result["key"]["public_key_pem"] = $key_details['key'];
    $result["key"]["spki_hash"] = spki_hash($export_pem);
  }
  return $result;
}











function csr_parse_json($csr) {
  //if csr or cert is pasted in form tis function parses the csr or it send the cert to cert_parse.
  global $random_blurp;
  global $timeout;
  $result = array();
  if (strpos($csr, "BEGIN CERTIFICATE REQUEST") !== false) { 
    $cert_data = openssl_csr_get_public_key($csr);
    $cert_details = openssl_pkey_get_details($cert_data);
    $cert_key = $cert_details['key'];
    $cert_subject = openssl_csr_get_subject($csr);
    $result["subject"] = $cert_subject;
    $result["key"] = $cert_key;
    $result["details"] = $cert_details; 
    if ($cert_details) {
      $result["csr_pem"] = $csr;
      $sans = get_sans_from_csr($csr);
      if(count($sans) > 1) {
        $result["csr_sans"] = $sans;
      }
    }
  } elseif (strpos($csr, "BEGIN CERTIFICATE") !== false) { 
    $result = cert_parse_json($csr, null, null, null, null, true);
  } else {
    $result = array("error" => "data not valid csr");
  }
  return $result;
}





?>