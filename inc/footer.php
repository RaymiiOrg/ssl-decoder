<?php
if(empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) != 'xmlhttprequest') {
  ?>
    <div class="footer">
      <div class="col-md-6 col-md-offset-1 container">
      <p class="text-muted">By <a href="https://raymii.org/s/">Remy van Elst</a>. License: GNU AGPLv3. <a href="https://github.com/RaymiiOrg/ssl-decoder">Source code</a>. <a href="https://github.com/RaymiiOrg/ssl-decoder#json-api">JSON API</a>. <strong><a href="https://cipherli.st/">Strong SSL Ciphers & Config settings @ Cipherli.st</a></strong>. Version: <?php echo $version; ?></p>
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
        //tooltips
        $('[data-toggle="tooltip"]').tooltip();   
        $(".tip-top").tooltip({placement : 'top'});
        $(".tip-right").tooltip({placement : 'right'});
        $(".tip-bottom").tooltip({placement : 'bottom'});
        $(".tip-left").tooltip({ placement : 'left'});
        
        //menu
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
