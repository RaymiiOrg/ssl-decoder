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

function pre_dump($var) {
  //this function is amazing whilst debugging.
  echo "<pre>";
  var_dump($var);
  echo "</pre>";
}

function utf8encodeNestedArray($arr) {
  // json_encode fails with binary data. utf-8 encode that first, some ca's like to encode images in their OID's (verisign, 1.3.6.1.5.5.7.1.12)...
  $encoded_arr = array();
  foreach ($arr as $key => $value) {
    if (is_array($value)) {
      $encoded_arr[utf8_encode($key)] = utf8encodeNestedArray($value);
    } else {
      $encoded_arr[utf8_encode($key)] = utf8_encode($value); 
    }
  }
  return $encoded_arr;
}

//two helper functions to check if string starts or end with, from stack overflow.
function startsWith($haystack, $needle) {
  // search backwards starting from haystack length characters from the end
  return $needle === "" || strrpos($haystack, $needle, -strlen($haystack)) !== FALSE;
}
function endsWith($haystack, $needle) {
  // search forward starting from end minus needle length characters
  if(!empty($haystack)) {
    return $needle === "" || strpos($haystack, $needle, strlen($haystack) - strlen($needle)) !== FALSE;
  }
}

function get_current_folder(){
  //not current OS folder, but current web folder.
  //used for relative links and css/js files
  $url = $_SERVER['REQUEST_URI']; 
  $parts = explode('/',$url);
  $folder = '';
  for ($i = 0; $i < count($parts) - 1; $i++) {
    $folder .= $parts[$i] . "/";
  }
  return $folder;
}

$current_folder = get_current_folder();

function gen_uuid() {
  //from stack overflow.
  return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
    // 32 bits for "time_low"
    mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),

    // 16 bits for "time_mid"
    mt_rand( 0, 0xffff ),

    // 16 bits for "time_hi_and_version",
    // four most significant bits holds version number 4
    mt_rand( 0, 0x0fff ) | 0x4000,

    // 16 bits, 8 bits for "clk_seq_hi_res",
    // 8 bits for "clk_seq_low",
    // two most significant bits holds zero and one for variant DCE1.1
    mt_rand( 0, 0x3fff ) | 0x8000,

    // 48 bits for "node"
    mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
  );
}

?>