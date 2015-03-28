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
    $hostname = mb_strtolower(get($_GET['host']));
    $host = parse_hostname($hostname);
    if ($host['port']) {
      $port = $host['port'];
    } else {
      $port = get($_GET['port'], '443');
    }
    $host = $host['hostname'];
    $csr = get($_GET['csr'], '');
    if ( !is_numeric($port) ) {
      $port = 443;
    }
    $stream = stream_context_create (array("ssl" => 
      array("capture_peer_cert" => true,
        "capture_peer_cert_chain" => true,
        "verify_peer" => false,
        "verify_peer_name" => false,
        "allow_self_signed" => true,
        "sni_enabled" => true)));
      $read_stream = stream_socket_client("ssl://$host:$port", $errno, $errstr, 2, STREAM_CLIENT_CONNECT, $stream);
      if ( $read_stream !== false ) {
        $context = stream_context_get_params($read_stream);
        $chain_data = $context["options"]["ssl"]["peer_certificate_chain"];
        $chain_length = count($chain_data);
        if (!empty($chain_data) && $chain_length < 10) {
    
  ?>
  <!-- Sidebar -->
  <div id="sidebar-wrapper">
    <nav>
    <ul class="sidebar-nav">
    <br>
      <li class="sidebar-brand">
        <h2>Navigation</h2>
      </li>
      <li><a href="#conndata"><strong>0</strong>: Connection Data</a></li>
      <?php
        foreach ($chain_data as $key => $value) {
          $nextkey = $key + 1;
          echo "<li><a href='#cert".$nextkey."'><strong>".$nextkey."</strong> : ". htmlspecialchars(get_cert_cn($value)) ."</a></li>";
        }
      ?>
      <li><a href="<?php echo(htmlspecialchars($current_folder)); ?>">Try another website</a></li>
      <li><hr></li>
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
      }
        ?>
<div id="page-content-wrapper">
  <div class="container-fluid">
    <div class="row">
      <?php
          if ( !isset($_GET['host']) || !isset($_GET['csr']) ) {
            ?>
            <div class="col-md-10 col-md-offset-1">
              <div class="page-header" >
                <h1>SSL Decoder</h1>
            </div>
            <div id='sslform'>
            <form class="form-horizontal">
              <p>Fill in either host + port or paste a CSR/Certficiate. Port defaults to 443.<br></p>
              <fieldset>

                <div class="form-group">
                  <label class="col-md-1 control-label" for="host">Host</label>  
                  <div class="col-md-5">
                    <input id="host" name="host" type="text" placeholder="raymii.org" class="form-control input-md" >
                  </div>
                  <label class="col-md-1 control-label" for="port">Port</label>  
                  <div class="col-md-2">
                    <input id="port" name="port" type="text" placeholder="443" class="form-control input-md">
                  </div>
                </div>
                <div class="form-group">
                  <div class="col-md-4 col-md-offset-1">
                    <div class="checkbox">
                      <label for="ciphersuites">
                        <input type="checkbox" name="ciphersuites" id="ciphersuites" value="1" checked="checked">
                        Enumerate Ciphersuites (takes longer)
                      </label>
                    </div>
                  </div>
                </div>

                <hr>

                <div class="form-group">
                  <label class="col-md-1 control-label" for="csr">CSR / Certificate</label>
                  <div class="col-md-5">                     
                    <textarea class="form-control" rows=6 id="csr" name="csr"></textarea>
                  </div>
                </div>

                <div class="form-group">
                  <div class="col-md-4">
                    <label class="col-md-2 col-md-offset-1 control-label" for="s"></label>
                    <button id="s" name="s" class="btn btn-primary" onsubmit="showElementbyID(true, 'preloader'); showElementbyID(false, 'sslform'); makeRequest('/ssl/?port=' + this.form.port.value + '&csr=' + this.form.csr.value + '&s=&host=' + this.form.host.value,, 'showContent');return false" onclick="showElementbyID(true, 'preloader'); showElementbyID(false, 'sslform'); makeRequest('/ssl/?port=' + this.form.port.value + '&csr=' + this.form.csr.value + '&ciphersuites=' + this.form.ciphersuites.value + '&s=&host=' + this.form.host.value, 'showContent');return false">Submit</button>
                  </div>
                </div>

              </fieldset>
            </form>
        </div>
        
        <div id="preloader"><p><img src="<?php echo(htmlspecialchars($current_folder)); ?>img/ajax-loader.gif" /><br>&nbsp;<br>The SSL Decoder is processing your request. Please wait a few moments.<br></p></div>

        <div id="resultDiv"></div>


            <?php
          } else {
            if(empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) != 'xmlhttprequest') {
              ?> 
              <div class="col-md-10 col-md-offset-1">
              <div class="page-header" >
                <h1>SSL Decoder</h1>
            </div>
            <?php
            // set back to 1 after debugging
            $write_cache = 1;
            if (!is_dir('results')) {
              mkdir('results');
            }
            $epoch = date('U');
            $random_bla = md5(uniqid(rand(), true));
          }
          $hostname = mb_strtolower(get($_GET['host']));
          $host = parse_hostname($hostname);
          if ($host['port']) {
            $port = $host['port'];
          } else {
            $port = get($_GET['port'], '443');
          }
          $host = $host['hostname'];
          $csr = get($_GET['csr'], '');
          if ( !is_numeric($port) ) {
            $port = 443;
          }

            if ( empty($csr) && !empty($host) ) {

              echo "<p><strong>This tool does not make conclusions. Please check the data and define the validity yourself!</strong></p><br>";

              $stream = stream_context_create (array("ssl" => 
                array("capture_peer_cert" => true,
                  "capture_peer_cert_chain" => true,
                  "verify_peer" => false,
                  "capture_session_meta" => true,
                  "verify_peer_name" => false,
                  "allow_self_signed" => true,
                  "sni_enabled" => true)));
              $read_stream = stream_socket_client("ssl://$host:$port", $errno, $errstr, 2,
                STREAM_CLIENT_CONNECT, $stream);

              if ( $read_stream === false ) {
                echo "<span class='text-danger'> Failed to connect:" . htmlspecialchars($errno) ." " . htmlspecialchars($errstr) . "</span>";
                echo "<hr>";
                $write_cache = 0;
              } else {
                $hostfilename = preg_replace("([^\w\s\d\-_~,;:\[\]\(\).])", '', $host);
                $hostfilename = preg_replace("([\.]{2,})", '', $host);
                $hostfilename = preg_replace("([^a-z0-9])", '', $host);
                $cache_filename = (string) "results/saved." . $hostfilename . "." . $epoch . "." . $random_bla . ".html";


                if ($write_cache == 1) {
                ?>
                <p>This result is saved at most 60 days on <a href="<?php echo(htmlspecialchars($current_folder) . $cache_filename); ?>">the following URL</a>. Do note that this might be deleted earlier if space runs out.</p>
                <?php
                }
                $context = stream_context_get_params($read_stream);
                $context_meta = stream_context_get_options($read_stream)['ssl']['session_meta'];
                $cert_data = openssl_x509_parse($context["options"]["ssl"]["peer_certificate"]);
                $chain_data = $context["options"]["ssl"]["peer_certificate_chain"];
                if (!empty($chain_data)) {
                  $chain_length = count($chain_data);
                  $chain_arr_keys  = ($chain_data);
                  foreach(array_keys($chain_arr_keys) as $key) {
                    $curr = $chain_data[$key];
                    $next = $chain_data[$key+1];
                    $prev = $chain_data[$key-1];

                    if ($key == 0) {

                      echo ssl_conn_metadata($host, $port, $chain_data);
                      echo "<div class='content'><section id='cert1'>";
                      echo "<header><h2 class='sticky'>Certificate for '". htmlspecialchars($host) ."'</h2></header>";

                      if ( $chain_length > $key) {
                        cert_parse($curr, $next, false, $host, $port, false);
                      } else {
                        cert_parse($curr, null, false, $host, $port, false);
                      }
                      echo "</section></div>";
                    } else {
                      if ($key == 10) {
                        echo "<span class='text-danger'>Error: Certificate Chain to long.</span><br>.";
                        $write_cache = 0;
                        continue;
                      }
                      if ($key > 10) {
                        $write_cache = 0;
                        continue;
                      }
                      $nextkey = $key + 1;
                      echo "<div class='content'><section id='cert" . $nextkey . "'>";
                      echo "<header><h2 class='sticky'>Chain $key - " . htmlspecialchars(get_cert_cn($curr)) . "</h2></header>";
                      
                      if ( $chain_length > $key) {
                        cert_parse($curr, $next, false, null, null, true);
                      } else {
                        cert_parse($curr, null, false, null, null, true);
                      }
                      echo "</section></div>";
                    }

                  }
                }

              }
            } else if (!empty($csr) && empty($host) ) {
                
              $cache_filename = (string) "results/saved.csr." . $epoch . "." . $random_bla . ".html";

                echo "<p><strong>This tool does not make conclusions. Please check the data and define the validity yourself!</strong><br>\n &nbsp;</p> <br>";
                if (strpos($csr, "BEGIN CERTIFICATE REQUEST") !== false) { 
                  echo "<header><h2>CSR </h2></header><p>";
                } else {
                  echo "<header><h2>Certificate </h2></header><p>";
                }
                cert_parse($csr, null, true);
              
            } else {
              echo "<span class='text-danger'> Host or Certificate required.</span>";
              echo "<hr>";
              $write_cache = 0;
            }
          }

        if ($write_cache == 1) {
        ?>
        <div class="panel panel-default">
          <div class="panel-heading">
            <h2 class="panel-title">Saved result</h2>
          </div>
          <div class="panel-body">
            <p>This result is saved at most 60 days on <a href="<?php echo(htmlspecialchars($current_folder) . $cache_filename); ?>">the following URL</a>. Do note that this might be deleted earlier if space runs out.</p>
          </div>
        </div>
        <?php
        }
        ?>
        </div>
      </div>
    </div>

    <?php
    if(empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) != 'xmlhttprequest') {
    ?>
      <div class="footer">
        <div class="col-md-6 col-md-offset-1 container">
          <p class="text-muted">By <a href="https://raymii.org/s/software/OpenSSL_Decoder.html">Remy van Elst</a>. License: GNU AGPLv3. <a href="https://github.com/RaymiiOrg/ssl-decoder">Source code</a>. <strong><a href="https://cipherli.st/">Strong SSL Ciphers & Config settings @ Cipherli.st</a></strong>. Version: 2.0</p>
        </div>
      </div>
    </div>
  </div>
    <?php
    }
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


<script>
    
    $(document).ready(function(){
        var aChildren = $("nav li").children(); // find the a children of the list items
        var aArray = []; // create the empty aArray
        for (var i=0; i < aChildren.length; i++) {    
            var aChild = aChildren[i];
            var ahref = $(aChild).attr('href');
            if(ahref && strStartsWith(ahref, "#") ) {
              aArray.push(ahref);
            }
        } // this for loop fills the aArray with attribute href values
        
        $(window).scroll(function(){

            var windowPos = $(window).scrollTop(); // get the offset of the window from the top of page
            var windowHeight = $(window).height(); // get the height of the window
            var docHeight = $(document).height();
            
            for (var i=0; i < aArray.length; i++) {
                var theID = aArray[i];
                var divPos = $(theID).offset().top; // get the offset of the div from the top of page
                var divHeight = $(theID).height(); // get the height of the div in question
                if (windowPos >= divPos && windowPos < (divPos + divHeight)) {
                    $("a[href='" + theID + "']").addClass("nav-active");
                } else {
                    $("a[href='" + theID + "']").removeClass("nav-active");
                }
            }
            
            if(windowPos + windowHeight == docHeight) {
                if (!$("nav li:last-child a").hasClass("nav-active")) {
                    var navActiveCurrent = $(".nav-active").attr("href");
                    $("a[href='" + navActiveCurrent + "']").removeClass("nav-active");
                    $("nav li:last-child a").addClass("nav-active");
                }
            }
        });
    });

</script>

  </body>
  </html>
<?php
if ($write_cache == 1) {
  if (!file_exists($cache_filename)) {
    file_put_contents($cache_filename, ob_get_contents());
  }
}

?>
