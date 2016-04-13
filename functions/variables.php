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

# timeout in seconds, used globally (curl, shell commands, etc)
$timeout = 120;

# max chain length (big chain slows down checks)
$max_chain_length = 10;

# Don't change stuff down here.
date_default_timezone_set('UTC');

$version = 3.2;

ini_set('default_socket_timeout', $timeout);

//used for random filenames in /tmp in crl and ocsp checks
$random_blurp = rand(10,99999);

// 2015-09-21 http://www.certificate-transparency.org/known-logs
// $ct_urls = ["https://ct.ws.symantec.com", 
//         "https://ct.googleapis.com/pilot",
//         "https://ct.googleapis.com/aviator", 
//         "https://ct.googleapis.com/rocketeer",
//         "https://ct1.digicert-ct.com/log",
//         "https://ct.izenpe.com",
//         "https://ctlog.api.venafi.com", 
//         "https://log.certly.io"];
$ct_urls = ["https://ct.googleapis.com/aviator"];


# 2014-11-10 (nov) from wikipedia
$ev_oids = array("1.3.6.1.4.1.34697.2.1", "1.3.6.1.4.1.34697.2.2", "1.3.6.1.4.1.34697.2.3", "1.3.6.1.4.1.34697.2.4", "1.2.40.0.17.1.22", "2.16.578.1.26.1.3.3", "1.3.6.1.4.1.17326.10.14.2.1.2", "1.3.6.1.4.1.17326.10.8.12.1.2", "1.3.6.1.4.1.6449.1.2.1.5.1", "2.16.840.1.114412.2.1", "2.16.840.1.114412.1.3.0.2", "2.16.528.1.1001.1.1.1.12.6.1.1.1", "2.16.840.1.114028.10.1.2", "0.4.0.2042.1.4", "0.4.0.2042.1.5", "1.3.6.1.4.1.13177.10.1.3.10", "1.3.6.1.4.1.14370.1.6", "1.3.6.1.4.1.4146.1.1", "2.16.840.1.114413.1.7.23.3", "1.3.6.1.4.1.14777.6.1.1", "2.16.792.1.2.1.1.5.7.1.9", "1.3.6.1.4.1.22234.2.5.2.3.1", "1.3.6.1.4.1.782.1.2.1.8.1", "1.3.6.1.4.1.8024.0.2.100.1.2", "1.2.392.200091.100.721.1", "2.16.840.1.114414.1.7.23.3", "1.3.6.1.4.1.23223.2", "1.3.6.1.4.1.23223.1.1.1", "2.16.756.1.83.21.0", "2.16.756.1.89.1.2.1.1", "2.16.840.1.113733.1.7.48.1", "2.16.840.1.114404.1.1.2.4.1", "2.16.840.1.113733.1.7.23.6", "1.3.6.1.4.1.6334.1.100.1", "2.16.840.1.114171.500.9", "1.3.6.1.4.1.36305.2");


function parse_hostname($u_hostname){
    # parses the URL and if no extea IP given, returns all A/AAAA records for that IP.
    # format raymii.org:1.2.34.56 should do SNI request to that ip.
    # parts[0]=host, parts[1]=ip
    $port = 0;
    $hostname = 0;
    $parts = explode(":", $u_hostname, 2);
    
    if (idn_to_ascii($parts[0])) {
        $parts[0] = idn_to_ascii($parts[0]);
    }
    $parts[0] = preg_replace('/\\s+/', '', $parts[0]);
    $parts[0] = preg_replace('/[^A-Za-z0-9\.\:-]/', '', $parts[0]);
    $hostname = mb_strtolower($parts[0]);
    
    if (count($parts) > 1) {
        $parts[1] = preg_replace('/\\s+/', '', $parts[1]);
        $parts[1] = preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $parts[1]);
        if (filter_var($parts[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) or filter_var($parts[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 )) {
            $ip = mb_strtolower($parts[1]);
        } 
    } else {
        if (filter_var($hostname, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 )) {
            $ip = $hostname;
        } else {    
            $dns_a_records = dns_get_record($hostname, DNS_A);
            $dns_aaaa_records = dns_get_record($hostname, DNS_AAAA);
            $dns_records = array_merge($dns_a_records, $dns_aaaa_records);
            if (count($dns_a_records) > 1 or count($dns_aaaa_records) > 1 or (count($dns_a_records) + count($dns_aaaa_records) > 1)) {
                $result = array('hostname' => $hostname, 'ip' => $ip, 'multiple_ip' => $dns_records);
                return $result;
            } else {
                $ip = fixed_gethostbyname($hostname);
            }
        }
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $ip = "[" . $ip . "]";
    }

    $result = array('hostname' => $hostname, 'ip' => $ip);
    return $result;
}

function choose_endpoint($ips, $host, $port, $fastcheck) {
    //if we detect multiple A/AAAA records, then show a page to choose the endpoint
    global $version;
    echo "<div id='page-content-wrapper'>\n";
    echo "<div class='container-fluid'>\n";
    echo "<div class='row'>\n";
    // if ajax-ed, don't show header again
    if(empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) != 'xmlhttprequest') {
      echo "<div class='col-md-10 col-md-offset-1'>\n";
      echo "<div class='page-header'>\n";
      echo "<h1><a style='color:black;' href=\"";
      echo(htmlspecialchars($current_folder));
      echo "\">SSL Decoder</a></h1>\n";
      echo "</div>\n";
    }
    //this div is hidden and only shown when an endpoint is choosen.
    echo "<div id='preloader'>\n";
    echo "<p>\n";
    echo "<img src=\"";
    echo(htmlspecialchars($current_folder));
    echo 'img/ajax-loader.gif" />';
    echo "<br>&nbsp;<br>\n";
    echo "The SSL Decoder is processing your request. Please wait a few moments.<br>\n";
    echo "</p>\n";
    echo "</div>\n";
    echo "<div id='resultDiv'></div>\n";
    echo "<div class='content' id='choose_endp'>\n<section id='choose_endpoint'>\n";
    echo "<header>\n<h2>Multiple endpoints for " . htmlspecialchars($host) . "</h2>\n</header>\n";
    echo "<p>We've found multiple A or AAAA records for " . htmlspecialchars($host) . ". Please choose the host you want to scan from the list below:</p>\n<br>\n";
    echo "<ul>\n";
    foreach ($ips as $ip) {
        echo "<li>";
        echo "<a onclick=\"showdiv('preloader'); hidediv('choose_endp');\" href=\"";
        echo htmlspecialchars($current_folder);
        echo "?host=";
        echo htmlspecialchars($host);
        echo ":";
        //ipv6 url's require [1234::5678] format
        if ($ip['type'] == 'A') {
            echo htmlspecialchars($ip['ip']);
        } elseif ($ip['type'] == 'AAAA') {
            echo "[";
            echo htmlspecialchars($ip['ipv6']);
            echo "]";
        }
        echo "&port=";
        echo htmlspecialchars($port);
        echo "&fastcheck=";
        if ($fastcheck == 1) {
            echo 1;
        } else {
            echo 0;
        }
        echo "\">";
        if ($ip['type'] == 'A') {
            echo htmlspecialchars($ip['ip']);
        } elseif ($ip['type'] == 'AAAA') {
            echo "[";
            echo htmlspecialchars($ip['ipv6']);
            echo "]";
        }
        echo " (port: ";
        echo htmlspecialchars($port);
        echo ")</a>";
        echo "</li>";
    }

    echo "</ul>\n";
    echo "</section></div>\n";
    echo "</div>\n";
    echo "</div>\n";
    echo "</div>\n";

    require_once("inc/footer.php");
    exit;
}

?>
