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

function check_json($host,$ip,$port,$fastcheck=0) {
  global $timeout;
  global $max_chain_length;
  global $ct_urls;
  $old_error_reporting = error_reporting();
  error_reporting(0);
  $data = [];
  $stream = stream_context_create (array("ssl" => 
    array("capture_peer_cert" => true,
    "capture_peer_cert_chain" => true,
    "verify_peer" => false,
    "peer_name" => $host,
    "verify_peer_name" => false,
    "allow_self_signed" => true,
    "capture_session_meta" => true,
    "sni_enabled" => true)));
  if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 )) {
    $connect_ip = "[" . $ip . "]";
  } else {
    $connect_ip = $ip;
  }
  $read_stream = stream_socket_client("ssl://$connect_ip:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream);
  if ( $read_stream === false ) {
    $data["error"] = ["Failed to connect: " . htmlspecialchars($errstr)];
    return $data;
  } else {
    $context = stream_context_get_params($read_stream);
    $context_meta = stream_context_get_options($read_stream)['ssl']['session_meta'];
    $cert_data = openssl_x509_parse($context["options"]["ssl"]["peer_certificate"]);
    $chain_data = $context["options"]["ssl"]["peer_certificate_chain"];
    $chain_length = count($chain_data);
    if (isset($chain_data) && $chain_length < $max_chain_length) {
      $chain_length = count($chain_data);
      $chain_arr_keys  = ($chain_data);
      foreach(array_keys($chain_arr_keys) as $key) {
        $curr = $chain_data[$key];
        $next = $chain_data[$key+1];
        $prev = $chain_data[$key-1];
        $chain_key = (string)$key+1;
        $include_chain = false;
        if ($key == 0) {
          $data["connection"] = ssl_conn_metadata_json($host, $ip, $port, $read_stream, $chain_data, $fastcheck);
          $data["chain"][$chain_key] = cert_parse_json($curr, $next, $host, true, $port, $include_chain);
        } else {
          $data["chain"][$chain_key] = cert_parse_json($curr, $next, null, false, $port, $include_chain);
        }
        // certificate transparency
        $data["certificate_transparency"] = [];
        if($fastcheck == 0) {
          foreach ($ct_urls as $ct_url) {
            $submitToCT = submitCertToCT($data["chain"], $ct_url);
            $ct_result = json_decode($submitToCT, TRUE);
            if ($ct_result === null
              && json_last_error() !== JSON_ERROR_NONE) {
              $result_ct = array('result' => $submitToCT);
              $data["certificate_transparency"][$ct_url] = $result_ct;
            } else {
             $data["certificate_transparency"][$ct_url] = $ct_result;
            }
          }
        }
      } 
    } else {
      $data["error"] = ["Chain too long."];
      return $data;
    }
  }
  error_reporting($old_error_reporting);
  return $data;
}

?>  