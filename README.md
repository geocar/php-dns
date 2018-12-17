This is a simple recursive resolver in php.

    <?php
    include("dns.inc");

    $r = new dns(dns::$ROOT_HINTS);
    var_dump($r->lookup("a", "www.github.com"));

e.g.

    array(2) {
      [0]=> string(12) "140.82.118.3"
      [1]=> string(12) "140.82.118.4"
    }

Supported RR:

* A
* NS
* CNAME
* TXT

