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

function tls_fallback_scsv($host, $ip, $port) {
    global $timeout;
    // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
    // if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    //     // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
    //     return false;
    // }
    $result = [];
    $protocols = ssl_conn_protocols($host, $ip, $port);
    if (count(array_filter($protocols)) > 1) {
        $result['protocol_count'] = count(array_filter($protocols));
        // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
        if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $fallback_test = shell_exec("echo | timeout $timeout openssl s_client -servername \"" . escapeshellcmd($host) . "\" -connect '" . $ip . ":" . escapeshellcmd($port) . "' -fallback_scsv -no_tls1_2 2>&1 >/dev/null");
        } else {
            $fallback_test = shell_exec("echo | timeout $timeout openssl s_client -servername \"" . escapeshellcmd($host) . "\" -connect " . escapeshellcmd($ip) . ":" . escapeshellcmd($port) . " -fallback_scsv -no_tls1_2 2>&1 >/dev/null");
        }
        if ( stripos($fallback_test, "SSL alert number 86") !== false ) {
            $result['tls_fallback_scsv_support'] = 1;
        }
    } else {
        $result['protocol_count'] = 1;
    }
    return $result;
}

?>