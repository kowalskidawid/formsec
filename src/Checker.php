<?php


namespace FormSec;

use Exception;

class Checker
{
    const IS_VPN_IP = 50;
    private int $score = 100;
    const DOMAIN_ON_CERT_ALERTS_LIST = 40;
    const IS_SERVER_IP = 20;
    const IS_NEW_DOMAIN = 20;
    const IS_XSS = 40;

    public function checkDomain(string $domain): void
    {
        if ($this->isOnCertAlertList($domain)) {
            $this->score -= self::DOMAIN_ON_CERT_ALERTS_LIST;
        }
        if ($this->isNewDomain($domain)) {
            $this->score -= self::IS_NEW_DOMAIN;
        }
    }

    private function isOnCertAlertList(string $domain): bool
    {
        $filePath = __DIR__ . '/../data/cert_domains.txt';
        $file = file_get_contents($filePath);
        return stripos($file, $domain) !== false;
    }

    public function getScore(): int
    {
        return $this->score;
    }

    public function checkIp(string $ip): void
    {
        $info = $this->getRipeInfo($ip);
        if ($this->isServerProvider($info)) {
            $this->score -= self::IS_SERVER_IP;
        }
        if ($this->isVpn($info)) {
            $this->score -= self::IS_VPN_IP;
        }
        if ($this->isScrapeProxy($ip)) {
            $this->score -= self::IS_VPN_IP;
        }

    }

    private function getRipeInfo(string $ip): string
    {
        $server = "whois.ripe.net";
        $port = 43;
        $fp = fsockopen($server, $port, $errno, $errstr, 10);
        if (!$fp) {
            return "Błąd połączenia: $errstr ($errno)";
        }
        fwrite($fp, "-B $ip\r\n");
        $response = "";
        while (!feof($fp)) {
            $response .= fgets($fp, 128);
        }
        fclose($fp);
        return $response;
    }

    private function isServerProvider(string $info): bool
    {
        $providers = [
            'ovh', 'soyoustart', 'kimsufi', 'amazon', 'aws', 'cloudfront', 'google',
            'gcp',
            '1e100',
            'microsoft',
            'azure',
            'msedge',
            'hetzner',
            'contabo',
            'digitalocean',
            'linode',
            'akamai',
            'cloudflare',
            'alibaba',
            'aliyun',
            'oracle',
            'oraclecloud',
            'vultr',
            'choopa',
            'scaleway',
            'netcup',
            'leaseweb',
            'ovhcloud',
            'fastly',
            'cdn77',
            'stackpath',
            'upcloud',
            'serverscom',
            'ikoula',
            'dedibox',
            'iliad',
            'nocix',
            'interserver',
            'rackspace',
            'dreamhost',
            'namecheap',
            'ovpn',
            'm247',
            'arubacloud',
            'aruba',
            'terrahost',
            'tpx',
            'packet',
            'equinix',
            'zare',
            'timeweb',
            'yandex',
            'rambler',
            'baidu',
            'tencent',
            'huawei',
            'mevspace',
            'snel',
            'myracloud',
            'nforce',
            'shinjiru',
            'seflow',
            'phoenixnap'
        ];
        $isServerProvider = false;
        foreach ($providers as $keyword) {
            if (stripos($info, $keyword) !== false) {
                $isServerProvider = true;
                break;
            }
        }
        return $isServerProvider;
    }
    private function isVpn(string $info): bool
    {
        $keywords = [
            'vpn', 'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'privateinternetaccess',
            'pia', 'mullvad', 'protonvpn', 'windscribe', 'torguard', 'ivpn', 'hide.me',
            'hidemyass', 'vyprvpn', 'strongvpn', 'purevpn', 'ipvanish', 'zenmate',
            'perfect-privacy', 'vpnsecure', 'vpnunlimited', 'fastestvpn', 'hotspotshield',
            'betternet', 'hola', 'privado', 'seed4me', 'vpnarea', 'airvpn', 'vpnbook',
            'tunnelbear', 'rocketvpn', 'atlasvpn', 'kasperskyvpn', 'browsec', 'bullguard',
            'slickvpn', 'vpn.ac', 'ibvpn', 'zoogvpn', 'hideip', 'vpn.ht', 'okayfreedom', 'touchvpn',
            'opera vpn', 'frootvpn', 'trust.zone', 'goosevpn', 'cryptostorm', 'blackvpn',
            'ovpn', 'ghostpath', 'anonymizer', 'i2p', 'tor-exit', 'exit-node', 'vpnserver',
            'vpn gateway', 'anonine', 'azirevpn', 'openvpn', 'openvpn technologies'
        ];
        $isVpn = false;
        foreach ($keywords as $keyword) {
            if (stripos($info, $keyword) !== false) {
                $isVpn = true;
                break;
            }
        }
        return $isVpn;
    }

    private function isNewDomain(string $domain)
    {
        $isNewDomain = false;
        $registrationDate = $this->getDomainRegistrationDate($domain);
        if ($registrationDate > date('Y-m-d', strtotime('-6 month'))) {
            $isNewDomain = true;
        }
        return $isNewDomain;
    }

    private function isScrapeProxy(string $ip): bool
    {
        $filePath = __DIR__ . '/../data/proxies.txt';
        $file = file_get_contents($filePath);
        return stripos($file, $ip) !== false;
    }

    public function checkContent(string $string)
    {
        if ($this->isXss($string)) {
            $this->score -= self::IS_XSS;
        }
    }

    private function isXss(string $content): bool
    {
        $decoded = html_entity_decode($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $cleaned = strtolower(trim($decoded));
        $patterns = [
            '/<\s*script.*?>.*?<\s*\/\s*script\s*>/is',
            '/on\w+\s*=\s*["\']?.*?["\']?/is',
            '/javascript\s*:/is',
            '/vbscript\s*:/is',
            '/data\s*:[^"]*/is',
            '/style\s*=\s*["\'].*?expression\s*\(.*?\).*?["\']/is',
            '/<\s*(iframe|embed|object|form|meta|link|style|base|svg|math|xss|xml|template|marquee|noscript).*?>/is',
            '/data\s*:\s*image\/.*?base64,.*?/is',
            '/(&#x*3c|<)\s*script/is',                          // <meta>
        ];
        $isXss = false;
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $cleaned)) {
                $isXss = true;
                break;
            }
        }
        return $isXss;
    }

    public function getDomainRegistrationDate($domain)
    {
        $tld = strtolower(pathinfo($domain, PATHINFO_EXTENSION));
        $whoisServers = [
            'ac' => 'whois.nic.ac',
            'ad' => 'whois.ripe.net',
            'ae' => 'whois.aeda.net.ae',
            'aero' => 'whois.aero',
            'af' => 'whois.nic.af',
            'ag' => 'whois.nic.ag',
            'ai' => 'whois.ai',
            'al' => 'whois.ripe.net',
            'am' => 'whois.amnic.net',
            'as' => 'whois.nic.as',
            'asia' => 'whois.nic.asia',
            'at' => 'whois.nic.at',
            'au' => 'whois.aunic.net',
            'aw' => 'whois.nic.aw',
            'ax' => 'whois.ax',
            'az' => 'whois.ripe.net',
            'ba' => 'whois.ripe.net',
            'bar' => 'whois.nic.bar',
            'be' => 'whois.dns.be',
            'berlin' => 'whois.nic.berlin',
            'best' => 'whois.nic.best',
            'bg' => 'whois.register.bg',
            'bi' => 'whois.nic.bi',
            'biz' => 'whois.neulevel.biz',
            'bj' => 'www.nic.bj',
            'bo' => 'whois.nic.bo',
            'br' => 'whois.nic.br',
            'br.com' => 'whois.centralnic.com',
            'bt' => 'whois.netnames.net',
            'bw' => 'whois.nic.net.bw',
            'by' => 'whois.cctld.by',
            'bz' => 'whois.belizenic.bz',
            'bzh' => 'whois-bzh.nic.fr',
            'ca' => 'whois.cira.ca',
            'cat' => 'whois.cat',
            'cc' => 'whois.nic.cc',
            'cd' => 'whois.nic.cd',
            'ceo' => 'whois.nic.ceo',
            'cf' => 'whois.dot.cf',
            'ch' => 'whois.nic.ch',
            'ci' => 'whois.nic.ci',
            'ck' => 'whois.nic.ck',
            'cl' => 'whois.nic.cl',
            'cloud' => 'whois.nic.cloud',
            'club' => 'whois.nic.club',
            'cn' => 'whois.cnnic.net.cn',
            'cn.com' => 'whois.centralnic.com',
            'co' => 'whois.nic.co',
            'co.nl' => 'whois.co.nl',
            'com' => 'whois.verisign-grs.com',
            'coop' => 'whois.nic.coop',
            'cx' => 'whois.nic.cx',
            'cy' => 'whois.ripe.net',
            'cz' => 'whois.nic.cz',
            'de' => 'whois.denic.de',
            'dk' => 'whois.dk-hostmaster.dk',
            'dm' => 'whois.nic.cx',
            'dz' => 'whois.nic.dz',
            'ec' => 'whois.nic.ec',
            'edu' => 'whois.educause.net',
            'ee' => 'whois.tld.ee',
            'eg' => 'whois.ripe.net',
            'es' => 'whois.nic.es',
            'eu' => 'whois.eu',
            'eu.com' => 'whois.centralnic.com',
            'eus' => 'whois.nic.eus',
            'fi' => 'whois.fi',
            'fo' => 'whois.nic.fo',
            'fr' => 'whois.nic.fr',
            'gb' => 'whois.ripe.net',
            'gb.com' => 'whois.centralnic.com',
            'gb.net' => 'whois.centralnic.com',
            'qc.com' => 'whois.centralnic.com',
            'ge' => 'whois.ripe.net',
            'gg' => 'whois.gg',
            'gi' => 'whois2.afilias-grs.net',
            'gl' => 'whois.nic.gl',
            'gm' => 'whois.ripe.net',
            'gov' => 'whois.nic.gov',
            'gr' => 'whois.ripe.net',
            'gs' => 'whois.nic.gs',
            'gy' => 'whois.registry.gy',
            'hamburg' => 'whois.nic.hamburg',
            'hiphop' => 'whois.uniregistry.net',
            'hk' => 'whois.hknic.net.hk',
            'hm' => 'whois.registry.hm',
            'hn' => 'whois2.afilias-grs.net',
            'host' => 'whois.nic.host',
            'hr' => 'whois.dns.hr',
            'ht' => 'whois.nic.ht',
            'hu' => 'whois.nic.hu',
            'hu.com' => 'whois.centralnic.com',
            'id' => 'whois.pandi.or.id',
            'ie' => 'whois.domainregistry.ie',
            'il' => 'whois.isoc.org.il',
            'im' => 'whois.nic.im',
            'in' => 'whois.inregistry.net',
            'info' => 'whois.afilias.info',
            'ing' => 'domain-registry-whois.l.google.com',
            'ink' => 'whois.centralnic.com',
            'int' => 'whois.isi.edu',
            'io' => 'whois.nic.io',
            'iq' => 'whois.cmc.iq',
            'ir' => 'whois.nic.ir',
            'is' => 'whois.isnic.is',
            'it' => 'whois.nic.it',
            'je' => 'whois.je',
            'jobs' => 'jobswhois.verisign-grs.com',
            'jp' => 'whois.jprs.jp',
            'ke' => 'whois.kenic.or.ke',
            'kg' => 'whois.domain.kg',
            'ki' => 'whois.nic.ki',
            'kr' => 'whois.kr',
            'kz' => 'whois.nic.kz',
            'la' => 'whois2.afilias-grs.net',
            'li' => 'whois.nic.li',
            'london' => 'whois.nic.london',
            'lt' => 'whois.domreg.lt',
            'lu' => 'whois.restena.lu',
            'lv' => 'whois.nic.lv',
            'ly' => 'whois.lydomains.com',
            'ma' => 'whois.iam.net.ma',
            'mc' => 'whois.ripe.net',
            'md' => 'whois.nic.md',
            'me' => 'whois.nic.me',
            'mg' => 'whois.nic.mg',
            'mil' => 'whois.nic.mil',
            'mk' => 'whois.ripe.net',
            'ml' => 'whois.dot.ml',
            'mo' => 'whois.monic.mo',
            'mobi' => 'whois.dotmobiregistry.net',
            'ms' => 'whois.nic.ms',
            'mt' => 'whois.ripe.net',
            'mu' => 'whois.nic.mu',
            'museum' => 'whois.museum',
            'mx' => 'whois.nic.mx',
            'my' => 'whois.mynic.net.my',
            'mz' => 'whois.nic.mz',
            'na' => 'whois.na-nic.com.na',
            'name' => 'whois.nic.name',
            'nc' => 'whois.nc',
            'net' => 'whois.verisign-grs.com',
            'nf' => 'whois.nic.cx',
            'ng' => 'whois.nic.net.ng',
            'nl' => 'whois.domain-registry.nl',
            'no' => 'whois.norid.no',
            'no.com' => 'whois.centralnic.com',
            'nu' => 'whois.nic.nu',
            'nz' => 'whois.srs.net.nz',
            'om' => 'whois.registry.om',
            'ong' => 'whois.publicinterestregistry.net',
            'ooo' => 'whois.nic.ooo',
            'org' => 'whois.pir.org',
            'paris' => 'whois-paris.nic.fr',
            'pe' => 'kero.yachay.pe',
            'pf' => 'whois.registry.pf',
            'pics' => 'whois.uniregistry.net',
            'pl' => 'whois.dns.pl',
            'pm' => 'whois.nic.pm',
            'pr' => 'whois.nic.pr',
            'press' => 'whois.nic.press',
            'pro' => 'whois.registrypro.pro',
            'pt' => 'whois.dns.pt',
            'pub' => 'whois.unitedtld.com',
            'pw' => 'whois.nic.pw',
            'qa' => 'whois.registry.qa',
            're' => 'whois.nic.re',
            'ro' => 'whois.rotld.ro',
            'rs' => 'whois.rnids.rs',
            'ru' => 'whois.tcinet.ru',
            'sa' => 'saudinic.net.sa',
            'sa.com' => 'whois.centralnic.com',
            'sb' => 'whois.nic.net.sb',
            'sc' => 'whois2.afilias-grs.net',
            'se' => 'whois.nic-se.se',
            'se.com' => 'whois.centralnic.com',
            'se.net' => 'whois.centralnic.com',
            'sg' => 'whois.nic.net.sg',
            'sh' => 'whois.nic.sh',
            'si' => 'whois.arnes.si',
            'sk' => 'whois.sk-nic.sk',
            'sm' => 'whois.nic.sm',
            'st' => 'whois.nic.st',
            'so' => 'whois.nic.so',
            'su' => 'whois.tcinet.ru',
            'sx' => 'whois.sx',
            'sy' => 'whois.tld.sy',
            'tc' => 'whois.adamsnames.tc',
            'tel' => 'whois.nic.tel',
            'tf' => 'whois.nic.tf',
            'th' => 'whois.thnic.net',
            'tj' => 'whois.nic.tj',
            'tk' => 'whois.nic.tk',
            'tl' => 'whois.domains.tl',
            'tm' => 'whois.nic.tm',
            'tn' => 'whois.ati.tn',
            'to' => 'whois.tonic.to',
            'top' => 'whois.nic.top',
            'tp' => 'whois.domains.tl',
            'tr' => 'whois.nic.tr',
            'travel' => 'whois.nic.travel',
            'tw' => 'whois.twnic.net.tw',
            'tv' => 'whois.nic.tv',
            'tz' => 'whois.tznic.or.tz',
            'ua' => 'whois.ua',
            'ug' => 'whois.co.ug',
            'uk' => 'whois.nic.uk',
            'uk.com' => 'whois.centralnic.com',
            'uk.net' => 'whois.centralnic.com',
            'ac.uk' => 'whois.ja.net',
            'gov.uk' => 'whois.ja.net',
            'us' => 'whois.nic.us',
            'us.com' => 'whois.centralnic.com',
            'uy' => 'nic.uy',
            'uy.com' => 'whois.centralnic.com',
            'uz' => 'whois.cctld.uz',
            'va' => 'whois.ripe.net',
            'vc' => 'whois2.afilias-grs.net',
            've' => 'whois.nic.ve',
            'vg' => 'ccwhois.ksregistry.net',
            'vu' => 'vunic.vu',
            'wang' => 'whois.nic.wang',
            'wf' => 'whois.nic.wf',
            'wiki' => 'whois.nic.wiki',
            'ws' => 'whois.website.ws',
            'xxx' => 'whois.nic.xxx',
            'xyz' => 'whois.nic.xyz',
            'yu' => 'whois.ripe.net',
            'za.com' => 'whois.centralnic.com',
            'fun' => 'whois.nic.fun',
            'click' => 'whois.nic.click',
            'shop' => 'whois.nic.shop'
        ];
        $server = $whoisServers[trim($tld)];
        if (empty($server)) {
            $server = 'whois.nic.' . $tld;
        }
        $fp = fsockopen($server, 43, $errno, $errMessage, 10);
        if (!$fp) {
            throw new Exception('WhoIs error: ' . $errMessage . ' ' . $errno);
        }
        $domain = $this->extractDomain($domain);
        fwrite($fp, "$domain\r\n");
        $response = '';
        while (!feof($fp)) {
            $response .= fgets($fp, 128);
        }
        fclose($fp);
        preg_match('/(Creation Date|Created On|created):\s*(.+)/i', $response, $matches);
        $date = '';
        if (!empty($matches[2])) {
            $date = $matches[2];
        }
        return $date;
    }

    public function extractDomain($domain)
    {
        $parts = explode(".", $domain);
        $count = count($parts);
        $doubleTLDs = ['co.uk', 'org.uk', 'gov.uk', 'com.pl', 'net.pl', 'edu.pl'];
        $tld = $parts[$count - 2] . '.' . $parts[$count - 1];
        if (in_array($tld, $doubleTLDs)) {
            $domain = $parts[$count - 3] . '.' . $tld;
        } else {
            $domain = $parts[$count - 2] . '.' . $parts[$count - 1];
        }
        return $domain;
    }

    public function extractTld($domain)
    {
        $parts = explode('.', $domain);
        $count = count($parts);
        $doubleTLDs = ['co.uk', 'org.uk', 'gov.uk', 'com.pl', 'net.pl', 'edu.pl'];
        $possibleTld = $parts[$count - 2] . '.' . $parts[$count - 1];
        $tld = $parts[$count - 1];
        if (in_array($possibleTld, $doubleTLDs)) {
            $tld = $possibleTld;
        }
        return $tld;
    }
}
