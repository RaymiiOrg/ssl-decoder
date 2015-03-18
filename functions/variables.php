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

$random_blurp = rand(1000,99999);

# 2014-11-10 (nov) from wikipedia
$ev_oids = array("1.3.6.1.4.1.34697.2.1", "1.3.6.1.4.1.34697.2.2", "1.3.6.1.4.1.34697.2.3", "1.3.6.1.4.1.34697.2.4", "1.2.40.0.17.1.22", "2.16.578.1.26.1.3.3", "1.3.6.1.4.1.17326.10.14.2.1.2", "1.3.6.1.4.1.17326.10.8.12.1.2", "1.3.6.1.4.1.6449.1.2.1.5.1", "2.16.840.1.114412.2.1", "2.16.840.1.114412.1.3.0.2", "2.16.528.1.1001.1.1.1.12.6.1.1.1", "2.16.840.1.114028.10.1.2", "0.4.0.2042.1.4", "0.4.0.2042.1.5", "1.3.6.1.4.1.13177.10.1.3.10", "1.3.6.1.4.1.14370.1.6", "1.3.6.1.4.1.4146.1.1", "2.16.840.1.114413.1.7.23.3", "1.3.6.1.4.1.14777.6.1.1", "2.16.792.1.2.1.1.5.7.1.9", "1.3.6.1.4.1.22234.2.5.2.3.1", "1.3.6.1.4.1.782.1.2.1.8.1", "1.3.6.1.4.1.8024.0.2.100.1.2", "1.2.392.200091.100.721.1", "2.16.840.1.114414.1.7.23.3", "1.3.6.1.4.1.23223.2", "1.3.6.1.4.1.23223.1.1.1", "2.16.756.1.83.21.0", "2.16.756.1.89.1.2.1.1", "2.16.840.1.113733.1.7.48.1", "2.16.840.1.114404.1.1.2.4.1", "2.16.840.1.113733.1.7.23.6", "1.3.6.1.4.1.6334.1.100.1", "2.16.840.1.114171.500.9", "1.3.6.1.4.1.36305.2");

$current_folder = get_current_folder();

function parse_hostname($u_hostname){
    # format raymii.org:8080 should auto parse port.
    # parts[0]=hostname, parts[1]=port
    $port = 0;
    $hostname = 0;
    $parts = explode(":", $u_hostname);
    if ((1 <= $parts[1]) && ($parts[1] <= 65535)) {
        $parts[1] = preg_replace('/\\s+/', '', $parts[1]);
        $parts[1] = preg_replace('/[^A-Za-z0-9\._-]/', '', $parts[1]);
        $port = mb_strtolower($parts[1]);
    }
    $parts[0] = preg_replace('/\\s+/', '', $parts[0]);
    $parts[0] = preg_replace('/[^A-Za-z0-9\.-]/', '', $parts[0]);
    $hostname = mb_strtolower($parts[0]);
    $result = array('hostname' => $hostname, 'port' => $port);
    return $result;
}

?>