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
    $result = [];
    $protocols = ssl_conn_protocols($host, $ip, $port);
    if (count(array_filter($protocols)) > 1) {
        $result['protocol_count'] = count(array_filter($protocols));
        $fallback_test = shell_exec("echo | timeout $timeout openssl s_client -servername \"" . escapeshellcmd($host) . "\" -connect " . escapeshellcmd($ip) . ":" . escapeshellcmd($port) . " -fallback_scsv -no_tls1_2 2>&1 >/dev/null");
        if ( stripos($fallback_test, "alert inappropriate fallback") !== false ) {
            $result['tls_fallback_scsv_support'] = 1;
        }
    } else {
        $result['protocol_count'] = 1;
    }
    return $result;
}

?>