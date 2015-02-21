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
            return;
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
            echo "<th>Not Expired</th>\n";
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
                      echo '<span class="text-success glyphicon glyphicon-ok-sign"></span> ';
                      echo '<span class="text-success">';
                      echo htmlspecialchars($ocsp_uri);
                      echo "<br>This update: " . htmlspecialchars($ocsp_result["This Update"]) . " - ";
                      echo "<br>Next update: " . htmlspecialchars($ocsp_result["Next Update"]) . "</span>";
                    } else if ( $ocsp_result["ocsp_verify_status"] == "revoked") {
                      echo '<span class="text-danger glyphicon glyphicon-remove-sign"></span> - ';
                      echo '<span class="text-danger">';
                      echo htmlspecialchars($ocsp_uri);
                      echo "<br>This update: " . htmlspecialchars($ocsp_result["This Update"]);
                      echo "<br>Next update: " . htmlspecialchars($ocsp_result["Next Update"]) . "</span>";
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
                  $export_pem = "";
                  openssl_x509_export($raw_cert_data, $export_pem);

                  if ( $key_details['rsa'] ) {
                    echo htmlspecialchars($key_details['bits']);
                    echo " bits RSA";
                  } else if ( $key_details['dsa'] ) {
                    echo htmlspecialchars($key_details['bits']);
                    echo " bits DSA";
                  } else if ( $key_details['dh'] ) {
                    echo htmlspecialchars($key_details['bits']);
                    echo " bits DH";
                  } else {
                    echo htmlspecialchars(var_dump($key_details['bits']));
                    echo " bits";
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
                  <?php 
                   if(!empty($export_pem)) {
                  ?>
                  <tr>
                <td>Certificate PEM </td>
                <td>
                  <div class="panel-group" id="pem-accordion<?php echo bcdechex($cert_data['serialNumber']); ?>" role="tablist" aria-multiselectable="true">
                    <div class="panel panel-default">
                      <div class="panel-heading" role="tab" id="pem-heading<?php echo bcdechex($cert_data['serialNumber']); ?>">
                        <h4 class="panel-title">
                          <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#pem-collapse<?php echo bcdechex($cert_data['serialNumber']); ?>" aria-expanded="false" aria-controls="pem-collapse<?php echo bcdechex($cert_data['serialNumber']); ?>">
                            Click to Open/Close
                          </a>
                        </h4>
                      </div>
                      <div id="pem-collapse<?php echo bcdechex($cert_data['serialNumber']); ?>" class="panel-collapse collapse" role="tabpanel" aria-labelledby="pem-heading<?php echo bcdechex($cert_data['serialNumber']); ?>">
                        <div class="panel-body">
                          <?php 
                          echo "<pre>";
                          echo htmlspecialchars($export_pem);
                          ?>
                          </pre>
                        </div>
                      </div>
                      </div>
                      </div>
                    </td>
                  </tr>
                  <?php
                  }
                  ?>
                  <?php 
                   if(!empty($key_details['key'])) {
                  ?>
                  <tr>
                <td>Public Key PEM </td>
                <td>
                  <div class="panel-group" id="pub-pem-accordion<?php echo bcdechex($cert_data['serialNumber']); ?>" role="tablist" aria-multiselectable="true">
                    <div class="panel panel-default">
                      <div class="panel-heading" role="tab" id="pub-pem-heading<?php echo bcdechex($cert_data['serialNumber']); ?>">
                        <h4 class="panel-title">
                          <a class="collapsed" data-toggle="collapse" data-parent="#accordion" href="#pub-pem-collapse<?php echo bcdechex($cert_data['serialNumber']); ?>" aria-expanded="false" aria-controls="pub-pem-collapse<?php echo bcdechex($cert_data['serialNumber']); ?>">
                            Click to Open/Close
                          </a>
                        </h4>
                      </div>
                      <div id="pub-pem-collapse<?php echo bcdechex($cert_data['serialNumber']); ?>" class="panel-collapse collapse" role="tabpanel" aria-labelledby="pub-pem-heading<?php echo bcdechex($cert_data['serialNumber']); ?>">
                        <div class="panel-body">
                          <?php 
                          echo "<pre>";
                          echo htmlspecialchars($key_details['key']);
                          ?>
                          </pre>
                        </div>
                      </div>
                      </div>
                      </div>
                    </td>
                  </tr>
                  <?php
                  }
                  ?>
                </tbody>
              </table>
              <?php
            }

?>