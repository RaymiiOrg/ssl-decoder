<?php
error_reporting(E_ALL & ~E_NOTICE);
$write_cache = 0;
$epoch = date('U');
$random_bla = md5(uniqid(rand(), true));
foreach (glob("functions/*.php") as $filename) {
  include $filename;
}

if ( isset($_GET['host']) && !empty($_GET['host'])) {
  $data = [];
  $hostname = mb_strtolower(get($_GET['host']));
  $hostname = parse_hostname($hostname);
  if ($hostname['multiple_ip']) {
    $data["error"] = ["Host format is incorrect. (use \$host:\$ip.)"];
  } 
  $host = $hostname['hostname'];
  $ip = $hostname['ip'];
  $port = get($_GET['port'], '443');
  if ( !is_numeric($port) ) {
    $port = 443;
  }
  $fastcheck = $_GET['fastcheck'];
  $write_cache = 1;
  $hostfilename = preg_replace("([^\w\s\d\-_~,;:\[\]\(\).])", '', $host);
  $hostfilename = preg_replace("([\.]{2,})", '', $host);
  $hostfilename = preg_replace("([^a-z0-9])", '', $host);
  $cache_filename = (string) "results/saved." . $hostfilename . "." . $epoch . "." . $random_bla . ".api.json";
  $data["data"] = check_json($host, $ip, $port, $fastcheck);
} elseif(isset($_GET['csr']) && !empty($_GET['csr'])) {
  $write_cache = 1;
  $cache_filename = (string) "results/saved.csr." . $epoch . "." . $random_bla . ".api.json";
  $data["data"]["chain"]["1"] = csr_parse_json($_GET['csr']);
} else {
  $data["error"] = ["Host is required"];
}

$data['version'] = $version;
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
  <?php
} else {
  header('Content-Type: application/json');
  echo json_encode($data);
}


if ($write_cache == 1) {
  if (!file_exists($cache_filename)) {
    file_put_contents($cache_filename, json_encode($data));
  }
}

?>

