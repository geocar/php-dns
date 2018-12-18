This is a simple recursive resolver in php.

    <?php
    include("dns.inc");

    $r = new dns(dns::$ROOT_HINTS);
    var_dump($r->lookup("a", "www.github.com"));
    var_dump($r->lookup("aaaa", "www.google.com"));
    var_dump($r->lookup("ptr", "78.206.58.216.in-addr.arpa"));
    var_dump($r->lookup("srv", "_ldap._tcp.google.com"));

		?>

e.g.

    array(2) {
      [0]=> string(12) "140.82.118.3"
      [1]=> string(12) "140.82.118.4"
    }
    array(1) {
      [0]=> string(24) "2a00:1450:4009:801::2004"
    }
    array(1) {
      [0]=> string(25) "lhr35s11-in-f14.1e100.net"
    }
    array(1) {
      [0]=> array(2) {
        [0]=> array(3) {
          ["prio"]=> int(5)
          ["weight"]=> int(0)
          ["port"]=> int(389)
        }
        [1]=> string(15) "ldap.google.com"
      }
    }

Supported RR:

* A
* AAAA
* NS
* CNAME
* TXT
* PTR
* SRV

