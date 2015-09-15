<!--
    Copyright (C) 2015 Remy van Elst

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->
<?php
error_reporting(E_ALL & ~E_NOTICE);
ob_start();
$write_cache = 0;

foreach (glob("functions/*.php") as $filename) {
  include $filename;
}
?>

<!doctype html>
<html lang="en">
<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SSL Decoder</title>  
  <link rel="stylesheet" href="<?php echo(htmlspecialchars($current_folder)); ?>css/bootstrap.min.css">
  <link rel="stylesheet" href="<?php echo(htmlspecialchars($current_folder)); ?>css/ssl.css">
  <script src="<?php echo(htmlspecialchars($current_folder)); ?>js/jquery.min.js"></script> 
  <script src="<?php echo(htmlspecialchars($current_folder)); ?>js/bootstrap.min.js"></script>
  <script src="<?php echo(htmlspecialchars($current_folder)); ?>js/ajax.js"></script>
</head>
<body>
  
  <a id="top-of-page"></a>
  <?php
  if ( isset($_GET['host']) && !empty($_GET['host'])) {
    echo '<div id="wrapper">';
    $data = [];
    $hostname = mb_strtolower(get($_GET['host']));
    $hostname = parse_hostname($hostname);
    $host = $hostname['hostname'];
    $port = get($_GET['port'], '443');
    if ( !is_numeric($port) ) {
      $port = 443;
    }
    if ($hostname['multiple_ip']) {
      choose_endpoint($hostname['multiple_ip'], $host, $port, $_GET['ciphersuites']);
    } 
    $ip = $hostname['ip'];
    $data["data"] = check_json($host,$ip,$port);
    if(isset($data["data"]["error"])) {
      $data["error"] = $data["data"]["error"];
      unset($data["data"]);
    }

    $chain_length = count($data["data"]["chain"]);
    $chain_data = $data["data"]["chain"];
    if ($chain_length >= 1 && $chain_length < 10) {
    
  ?>
  <!-- Sidebar -->
  <div id="sidebar-wrapper">
    <nav>
      <ul class="sidebar-nav">
        <br>
        <li class="sidebar-brand">
          <h2>Navigation</h2>
        </li>
        <?php
          if (count($data["data"]["connection"]["warning"]) >= 1) {
            $warntxt = " <sup>(<strong>".htmlspecialchars(count(array_unique($data["data"]["connection"]["warning"])))."</strong>)</sup>";
          }
        ?>
        <li><a href="#conndata"><strong>0</strong>: Connection Data <?php echo $warntxt; $warntxt = ''; ?></a></li>
        <?php
        foreach ($chain_data as $key => $value) {
          if (count($value['warning']) >= 1) {
            $warntxt = " <sup>(<strong>".htmlspecialchars(count($value['warning']))."</strong>)</sup>";
          }
          echo "<li><a href='#cert".(string)$key."'><strong>".$key."</strong> : ". htmlspecialchars($value["cert_data"]["subject"]["CN"]) . $warntxt . "</a></li>";
          $warntxt = "";
        }
        ?>
        <li><a href="<?php echo(htmlspecialchars($current_folder)); ?>">Try another website</a></li>
        <li><hr></li>
        <li><a href="https://certificatemonitor.org/">Certificate Expiry Monitor</a></li>
        <li><a href="https://cipherli.st/">Strong Cipherlists</a></li>
        <li><a href="https://raymii.org/s/tutorials/Strong_SSL_Security_On_Apache2.html">Apache SSL Tutorial</a></li>
        <li><a href="https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html">NGINX SSL Tutorial</a></li>
        <li><a href="https://raymii.org/s/tutorials/Strong_SSL_Security_On_lighttpd.html">Lighttpd SSL Tutorial</a></li>
        <li><a href="https://raymii.org">Raymii.org</a></li>
      </ul>
    </nav>
  </div>
  <!-- /#sidebar-wrapper -->
  <?php
    }
  }
      
  if (empty($_GET['host']) && empty($_GET['csr'])) {
    require_once("inc/form.php");
  } else {
    echo "<div id='page-content-wrapper'>";
    echo "<div class='container-fluid'>";
    echo "<div class='row'>";
    // if ajax-ed, don't show header again
    if(empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) != 'xmlhttprequest') {
      echo "<div class='col-md-10 col-md-offset-1'>";
      echo "<div class='page-header'>";
      echo "<h1><a style='color:black;' href=\"";
      echo(htmlspecialchars($current_folder));
      echo "\">SSL Decoder</a></h1>";
      echo "</div>";
      // set back to 1 after debugging
      $write_cache = 1;
      if (!is_dir('results')) {
        mkdir('results');
      }
      $epoch = date('U');
      $random_bla = md5(uniqid(rand(), true));
    }
  
    if ( !empty($host) ) {
      if ( !empty($data["error"]) ) {
        echo "<span class='text-danger'>" . htmlspecialchars($data["error"][0]) . "</span>";
        echo "<hr>";
        $write_cache = 0;
      } else {

        $hostfilename = preg_replace("([^\w\s\d\-_~,;:\[\]\(\).])", '', $host);
        $hostfilename = preg_replace("([\.]{2,})", '', $host);
        $hostfilename = preg_replace("([^a-z0-9])", '', $host);
        $cache_filename = (string) "results/saved." . $hostfilename . "." . $epoch . "." . $random_bla . ".html";
        $cache_filename_json = (string) "results/saved." . $hostfilename . "." . $epoch . "." . $random_bla . ".json";

        echo "<p><strong>This tool does not make conclusions. Please check the data and define the validity yourself!</strong></p>";

        if ($write_cache == 1) {
          echo "<p>This result is saved at most 60 days on <a href=\"";
          echo(htmlspecialchars($current_folder) . $cache_filename); 
          echo "\">the following URL</a>. Do note that this might be deleted earlier if space runs out.<br></p>";
        }

        echo "<script type='text/javascript'>document.title = \"" . htmlspecialchars($host) . ":" . htmlspecialchars($port) . " - SSL Decoder \"</script>";

        echo "<p>Receive notifications when this certificate is about to expire with my other service, <a href='https://certificatemonitor.org/'>Certificate Monitor</a>.</p>";

        // connection data
        echo "<div class='content'><section id='conndata'>";
        echo "<header><h2>Connection Data for " . htmlspecialchars($host) . " / " . htmlspecialchars($ip) . "</h2></header>";
        ssl_conn_metadata($data["data"]["connection"]);
        echo "</section></div>";

        // certificates
        foreach ($data["data"]["chain"] as $key => $value) {
          echo "<div class='content'><section id='cert" . $key . "'>";
          echo "<header><h2>Certificate for '". htmlspecialchars($value["cert_data"]["subject"]["CN"]) ."'</h2></header>";
          cert_parse($value);
          echo "</section></div>";
        }
      }     
    } elseif (!empty($_GET['csr']) ) {
      $data = csr_parse_json($_GET['csr']);
      echo "<p><strong>This tool does not make conclusions. Please check the data and define the validity yourself!</strong><br>\n &nbsp;</p>";
      $cache_filename = (string) "results/saved.csr." . $epoch . "." . $random_bla . ".html";
      $cache_filename_json = (string) "results/saved.csr." . $epoch . "." . $random_bla . ".json";
      if ($write_cache == 1) {
        echo "This result is saved at most 60 days on <a href=\"";
        echo(htmlspecialchars($current_folder) . $cache_filename); 
        echo "\">the following URL</a>. Do note that this might be deleted earlier if space runs out.";
      }

      if (strpos($_GET['csr'], "BEGIN CERTIFICATE REQUEST") !== false) { 
        echo "<header><h2>CSR </h2></header><p>";
        csr_parse($data);
      } else {
        echo "<header><h2>Certificate </h2></header><p>";
        cert_parse($data);
      }
    } else {
      echo "<span class='text-danger'> Host or Certificate required.</span>";
      echo "<hr>";
      $write_cache = 0;
    }
  }

  echo "</div>";
  echo "</div>";
  echo "</div>";

require_once("inc/footer.php");

if ($write_cache == 1) {
  if (!file_exists($cache_filename)) {
    file_put_contents($cache_filename, ob_get_contents());
  }
  if (is_array($data)) {
    $json_data = json_encode(utf8encodeNestedArray($data));
  }
  if (!file_exists($cache_filename_json)) {
    file_put_contents($cache_filename_json, $json_data);
  }
}

?>
