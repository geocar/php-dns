<?php

class dns {
	private $cache;
	private $roots;

	public static $RR = array("a" => 1, "mx" => 15, "ns" => 2, "cname" => 5, "txt" => 16); // rfc1034/1035
	public static $ROOT_HINTS = array( // https://www.iana.org/domains/root/files
		"a.root-servers.net" => "198.41.0.4",
		"b.root-servers.net" => "199.9.14.201",
		"c.root-servers.net" => "192.33.4.12",
		"d.root-servers.net" => "199.7.91.13",
		"e.root-servers.net" => "192.203.230.10",
		"f.root-servers.net" => "192.5.5.241",
		"g.root-servers.net" => "192.112.36.4",
		"h.root-servers.net" => "198.97.190.53",
		"i.root-servers.net" => "192.36.148.17",
		"j.root-servers.net" => "192.58.128.30",
		"k.root-servers.net" => "193.0.14.129",
		"l.root-servers.net" => "199.7.83.42",
		"m.root-servers.net" => "202.12.27.33"
	);

	public function __construct($roots, $timeout = 2) {
		$this->cache   = array();
		$this->roots   = $roots;
		$this->timeout = $timeout;
		foreach ($roots as $name => $ip) $this->cache["a,$name"] = $ip;
	}

	public function lookup($rr, $name, $at=".", $depth=0, $tries=0, $proto="udp") {
		if($tries > 10 || $depth > 12) return false;

		$rr    = strtolower($rr);
		$name  = strtolower($name);
		$rrkey = "$rr,$name";

		if(isset($this->cache[$rrkey])) return $this->cache[$rrkey];

		if($at == ".") {
			foreach ($this->roots as $_root_name => $ip) {
				$res = $this->lookup($rr, $name, $ip, $depth + 1);
				if($res !== false) return $res;
			}
			return array(); // nxdomain
		}

		$qq = rand(10, 77);
		$data = pack('n6', $qq, 0x0100, 1, 0, 0, 0);
		foreach (explode('.', $name) as $bit) {
			$l = strlen($bit);
			if($l > 192) return false; // bad name?
			$data .= chr($l) . $bit;
    }
		$data .= chr(0) . pack('n2', self::$RR[$rr], 1);

		$fp = fsockopen("{$proto}://$at", 53, $errno, $errstr, $this->timeout);
		if(!isset($fp)) throw new Exception($errstr, $errno);
		fwrite($fp,$data);
		$raw = fread($fp, 16384);
		fclose($fp);

		$head = unpack("nid/nspec/nqdcount/nancount/nnscount/narcount", substr($raw, 0, 12));
		if($head['id'] != $qq || $head['qdcount'] != 1) return $this->lookup($rr, $name, $at, $depth, $tries + 1);
		if(($head['spec'] >> 8) & 2) return $this->lookup($rr, $name, $at, $depth, $tries, "tcp"); // truncated bit

		$rcode = $head['spec'] & 15;
		if($rcode == 3) return array();
		if($rcode != 0) return false; // internal error

		$read_encoded_name = function(&$off) use(&$raw, &$read_encoded_name) {
			$rn = "";
			// read an encoded name
			while($off < strlen($raw)) {
				$c = ord(substr($raw, $off, 1));
				if($c >= 192) {
					$p1 = $c & 63; 
					$p2 = ord(substr($raw, $off+1, 2));
					$ptr = ($p1 << 8) | $p2;
					if($ptr < 12 || $ptr >= strlen($raw)) return false;
					$rn .= $read_encoded_name($ptr) . '.';
					$off += 2;
					break;
	
				} elseif($c > 0) {
					$rn .= substr($raw, $off + 1, $c) . ".";
					$off += 1 + $c;
				} else {
					$off ++;
					break;
				}
			}
			if($off > strlen($raw)) return false;
			$rn = rtrim($rn, '.');
			$rn = strtolower($rn);
			return $rn;
		};
		$off = 12;
		$z = $read_encoded_name($off);
		if($z != $name) return false; // bad name
		$off += 4; // skip qtype and qclass


		$answer = array();
		$auth = array();
		$records = $head['ancount'] + $head['nscount'] + $head['arcount'];
		for($i = 0; $i < $records && $off < strlen($raw); ++$i) {
			$rn = $read_encoded_name($off);
			if($off > (strlen($raw) - 10)) break;
			$rhead = unpack('ntype/nclass/Nttl/nrdlength', substr($raw, $off, 10));
			$rdata = substr($raw, $off, $rhead['rdlength']);
			$off += 10;
			$text = "";
			if($rhead['type'] == self::$RR['ns']) { $ptr = $off; $text = $read_encoded_name($ptr); }
			elseif($rhead['type'] == self::$RR['cname'] || $rhead['type'] == self::$RR['txt']) {
				$ptr = $off; $text = $read_encoded_name($ptr);
				if($rr == 'a') return $this->lookup($rr, $text, ".", $depth + 1);
			} elseif($rhead['type'] == self::$RR['a']) {
				$text = sprintf("%u.%u.%u.%u",
					ord(substr($raw, $off, 1)),
					ord(substr($raw, $off + 1, 1)),
					ord(substr($raw, $off + 2, 1)),
					ord(substr($raw, $off + 3, 1)));
			} elseif($rhead['type'] == self::$RR['mx']) {
				$ptr = $off + 2; $mm = unpack('npref', substr($raw, $off, 2));
				$z = $read_encoded_name($ptr);
				$text = array($mm['pref'], $z);
			}

			if($i < $head['ancount']) {
				$answer[] = $text;
			} elseif($i < $head['ancount'] + $head['nscount']) {
				if($rhead['type'] == self::$RR['ns']) {
					$auth[] = $text;
				}
			} elseif($rhead['type'] == self::$RR['a']) {
				if(substr($rn, strlen($rn) - (strlen($name)+1)) == ".$name") {
					$this->cache["a,$rn"] = $text;
				}
			}
			$off += $rhead['rdlength'];
		}
		if(empty($answer) && !empty($auth)) {
			foreach ($auth as $at) {
				$res = $this->lookup($rr, $name, $at, $depth + 1);
				if($res !== false) return $res;
			}
			return false;
		}
		return $answer;
	}
}
