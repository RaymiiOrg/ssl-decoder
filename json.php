<?php
error_reporting(E_ALL & ~E_NOTICE);
foreach (glob("functions/*.php") as $filename) {
  include $filename;
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

function check_json($host,$port) {
  $data = [];
  $stream = stream_context_create (array("ssl" => 
    array("capture_peer_cert" => true,
    "capture_peer_cert_chain" => true,
    "verify_peer" => false,
    "verify_peer_name" => false,
    "allow_self_signed" => true,
    "capture_session_meta" => true,
    "sni_enabled" => true)));
  $read_stream = stream_socket_client("ssl://$host:$port", $errno, $errstr, 2, STREAM_CLIENT_CONNECT, $stream);
  if ( $read_stream === false ) {
    $data["error"] = ["Failed to connect: " . htmlspecialchars($errstr)];
    return $data;
  } else {
    $context = stream_context_get_params($read_stream);
    $context_meta = stream_context_get_options($read_stream)['ssl']['session_meta'];
    $cert_data = openssl_x509_parse($context["options"]["ssl"]["peer_certificate"]);
    $chain_data = $context["options"]["ssl"]["peer_certificate_chain"];
    $chain_length = count($chain_data);
    if (isset($chain_data) && $chain_length < 10) {
      $chain_length = count($chain_data);
      $chain_arr_keys  = ($chain_data);
      foreach(array_keys($chain_arr_keys) as $key) {
        $curr = $chain_data[$key];
        $next = $chain_data[$key+1];
        $prev = $chain_data[$key-1];
        $chain_key = (string)$key+1;
        if ($key == 0) {
          $data["connection"] = ssl_conn_metadata_json($host, $port, $read_stream, $chain_data);
          $data["chain"][$chain_key] = cert_parse_json($curr, $next, false, $host, true);
        } else {
          $data["chain"][$chain_key] = cert_parse_json($curr, $next, false, null, false);
        }
      }
    } else {
      $data["error"] = ["Chain too long."];
      return $data;
    }
  }
  return $data;
}

if ( isset($_GET['host']) && !empty($_GET['host'])) {
  $data = [];
  $hostname = mb_strtolower(get($_GET['host']));
  $host = parse_hostname($hostname);
  if ($host['port']) {
    $port = $host['port'];
  } else {
    $port = get($_GET['port'], '443');
  }
  $host = $host['hostname'];
  if ( !is_numeric($port) ) {
    $port = 443;
  }
  $data["data"] = check_json($host,$port);

} elseif(isset($_GET['csr']) && !empty($_GET['csr'])) {
  $data["data"]["chain"]["1"] = csr_parse_json($_GET['csr']);

} else {
  $data["error"] = ["Host is required"];

}

$data = utf8encodeNestedArray($data);

if(isset($data["data"]["error"])) {
  $data["error"] = $data["data"]["error"];
  unset($data["data"]);
}

if ($_GET["type"] == "pretty") {
  header('Content-Type: text/html');
  echo "<pre>";
  echo htmlspecialchars(json_encode($data,JSON_PRETTY_PRINT));
  echo "</pre>";
  ?>
  <!-- Piwik -->
  <script type="text/javascript">
    var _paq = _paq || [];
    _paq.push(['trackPageView']);
    _paq.push(['enableLinkTracking']);
    (function() {
      var u="//hosted-oswa.org/piwik/";
      _paq.push(['setTrackerUrl', u+'piwik.php']);
      _paq.push(['setSiteId', 34]);
      var d=document, g=d.createElement('script'), s=d.getElementsByTagName('script')[0];
      g.type='text/javascript'; g.async=true; g.defer=true; g.src=u+'piwik.js'; s.parentNode.insertBefore(g,s);
    })();
  </script>
  <noscript><p><img src="//hosted-oswa.org/piwik/piwik.php?idsite=34" style="border:0;" alt="" /></p></noscript>
  <!-- End Piwik Code -->
  <?
} else {
  header('Content-Type: application/json');
  echo json_encode($data);
}

?>

