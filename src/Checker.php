<?php


namespace FormSec;

use Exception;

class Checker
{
    const IS_VPN_IP = 50;
    const IS_RUSSIAN_SERVER_PROVIDER = 30;
    const MIME_TYPE_NOT_MATCH = 50;
    const CONTAINS_VIRUS = 80;
    const EXECUTABLE_FILE = 30;
    private $score = 100;
    const DOMAIN_ON_CERT_ALERTS_LIST = 40;
    const IS_SERVER_IP = 20;
    const IS_NEW_DOMAIN = 20;
    const IS_XSS = 40;
    const OTHER_COUNTRY = 30;
    const CONTAINS_PASTE_BIN_URL = 10;
    const CONTAINS_CYRILLIC = 30;
    const CONTAINS_OTHER_LANGUAGE = 15;
    const INVALID_EMAIL_ADDRESS = 40;

    private $message;
    private $email;
    private $ipAddress;
    private $attachments;
    private $virusTotalApiKey;

    public function __construct($message, $email, $ipAddress, $attachments = [], $virusTotalApiKey = '')
    {
        $this->message = $message;
        $this->email = $email;
        $this->ipAddress = $ipAddress;
        $this->attachments = $attachments;
        $this->virusTotalApiKey = $virusTotalApiKey;
    }

    public function check()
    {
        $this->score = 100;
        $this->checkIp($this->ipAddress);

        $domainFromEmail = explode('@', $this->email);
        if (count($domainFromEmail) != 2) {
            $this->score -= self::INVALID_EMAIL_ADDRESS;
        } else {
            $this->checkDomain($domainFromEmail[1]);
        }
        $this->checkContent($this->message);
        $this->checkAttachments();
        if ($this->score < 0) {
            $this->score = 0;
        }
        return $this->score;
    }

    private function checkDomain($domain)
    {
        if ($this->isOnCertAlertList($domain)) {
            $this->score -= self::DOMAIN_ON_CERT_ALERTS_LIST;
        }
        if ($this->isNewDomain($domain)) {
            $this->score -= self::IS_NEW_DOMAIN;
        }
    }

    public function isOnCertAlertList($domain)
    {
        $localPath = __DIR__ . '/../data/cert_domains.txt';
        $useLocal = file_exists($localPath) && (time() - filemtime($localPath) < 30 * 24 * 60 * 60);

        if ($useLocal) {
            $file = file_get_contents($localPath);
        } else {
            $url = 'https://hole.cert.pl/domains/v2/domains.txt';
            $context = stream_context_create(['http' => ['timeout' => 3]]);
            $file = @file_get_contents($url, false, $context);
            if ($file !== false) {
                @file_put_contents($localPath, $file);
            } else if (file_exists($localPath)) {
                $file = file_get_contents($localPath);
            } else {
                return false;
            }
        }

        return stripos($file, $domain) !== false;
    }

    public function getScore()
    {
        return $this->score;
    }

    private function checkIp($ip)
    {
        $info = $this->getRipeInfo($ip);
        if ($this->isServerProvider($info)) {
            $this->score -= self::IS_SERVER_IP;
        }
        if ($this->isVpn($info)) {
            $this->score -= self::IS_VPN_IP;
        }
        if ($this->isRussianServerProvider($info)) {
            $this->score -= self::IS_RUSSIAN_SERVER_PROVIDER;
        }
        if ($this->isScrapeProxy($ip)) {
            $this->score -= self::IS_VPN_IP;
        }
    }

    private function getRipeInfo($ip)
    {
        $server = "whois.ripe.net";
        $port = 43;
        $fp = fsockopen($server, $port, $errno, $errstr, 10);
        if (!$fp) {
            throw new Exception('WhoIs error: ' . $errno . ' ' . $errstr);
        }
        fwrite($fp, "-B $ip\r\n");
        $response = "";
        while (!feof($fp)) {
            $response .= fgets($fp, 128);
        }
        fclose($fp);
        return $response;
    }

    private function isServerProvider($info)
    {
        $providers = [
            'ovh', 'soyoustart', 'kimsufi', 'amazon', 'aws', 'cloudfront', 'google',
            'gcp', '1e100', 'microsoft', 'azure', 'msedge', 'hetzner', 'contabo',
            'digitalocean', 'linode', 'akamai', 'cloudflare', 'alibaba', 'aliyun',
            'oracle', 'oraclecloud', 'vultr', 'choopa', 'scaleway', 'netcup', 'leaseweb',
            'ovhcloud', 'fastly', 'cdn77', 'stackpath', 'upcloud', 'serverscom', 'ikoula',
            'dedibox', 'iliad', 'nocix', 'interserver', 'rackspace', 'dreamhost', 'namecheap',
            'ovpn', 'm247', 'arubacloud', 'aruba', 'terrahost', 'tpx', 'packet', 'equinix',
            'zare', 'timeweb', 'yandex', 'rambler', 'baidu', 'tencent', 'huawei', 'mevspace',
            'snel', 'myracloud', 'nforce', 'shinjiru', 'seflow', 'phoenixnap', 'altushost',
            'HOSTiQ', 'ukrainian', 'Tuthost', 'DeltaHost', 'Beget', 'Timeweb', 'Selectel',
            'SpaceWeb', 'Hoster', 'Zomro', 'FirstVDS', 'Fornex', 'LEASEWEB'
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

    private function isVpn($info)
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

    private function isNewDomain($domain)
    {
        $isNewDomain = false;
        $registrationDate = $this->getDomainRegistrationDate($domain);
        if (!empty($registrationDate) && $registrationDate > date('Y-m-d', strtotime('-6 month'))) {
            $isNewDomain = true;
        }
        return $isNewDomain;
    }

    private function isScrapeProxy($ip)
    {
        $localPath = __DIR__ . '/../data/proxies.txt';
        $useLocal = file_exists($localPath) && (time() - filemtime($localPath) < 30 * 24 * 60 * 60);

        if ($useLocal) {
            $file = file_get_contents($localPath);
        } else {
            $url = 'https://formsec.pl/data/proxies.txt';
            $context = stream_context_create(['http' => ['timeout' => 3]]);
            $file = @file_get_contents($url, false, $context);
            if ($file !== false) {
                @file_put_contents($localPath, $file); // opcjonalnie zaktualizuj lokalnie
            } else if (file_exists($localPath)) {
                $file = file_get_contents($localPath); // fallback
            } else {
                return false;
            }
        }

        return stripos($file, $ip) !== false;
    }

    private function checkContent($content)
    {
        if ($this->isXss($content)) {
            $this->score -= self::IS_XSS;
        }
        if ($this->containsPasteBinUrl($content)) {
            $this->score -= self::CONTAINS_PASTE_BIN_URL;
        }
        if ($this->containsCyrillic($content)) {
            $this->score -= self::CONTAINS_CYRILLIC;
        } elseif ($this->containsOtherLanguage($content)) {
            $this->score -= self::CONTAINS_OTHER_LANGUAGE;
        }
        preg_match_all('/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/i', $content, $matches);
        if (!empty($matches[0])) {
            $domains = $matches[0];
            foreach ($domains as $domain) {
                $this->checkDomain($domain);
            }
        }
    }

    private function isXss($content)
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
            '/(&#x*3c|<)\s*script/is',
            '/<\s*\/?\s*[a-z][a-z0-9]*\b[^>]*>/i',
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
        $tld = trim($tld);
        $server = 'whois.nic.' . $tld;
        if (isset($whoisServers[$tld])) {
            $server = $whoisServers[$tld];
        }
        $fp = @fsockopen($server, 43, $errno, $errMessage, 10);
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
        $doubleTLDs = ['co.uk', 'org.uk', 'gov.uk', 'com.pl', 'net.pl', 'edu.pl', 'co.in', 'edu.vn'];
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

    private function isRussianServerProvider($info)
    {
        preg_match('/country:\s*(\w{2})/i', $info, $matches);
        $isRussianServerProvider = false;
        if (!empty($matches[1]) && $matches[1] == 'RU') {
            $isRussianServerProvider = true;
        }
        return $isRussianServerProvider;
    }

    private function containsPasteBinUrl($message)
    {
        $keywords = [
            'pastebin.com',
            'devpost.com'
        ];
        $containsPasteBinUrl = false;
        foreach ($keywords as $keyword) {
            if (stripos($message, $keyword) !== false) {
                $containsPasteBinUrl = true;
                break;
            }
        }
        return $containsPasteBinUrl;
    }

    private function containsCyrillic($content)
    {
        return preg_match('/\p{Cyrillic}/u', $content);
    }

    private function containsOtherLanguage($content)
    {
        $polishWords = ['i', 'że', 'się', 'jest', 'na', 'do', 'nie', 'z', 'jak', 'to', 'co', 'dla', 'tak', 'ale', 'czy', 'ten', 'być'];
        $englishWords = ['the', 'and', 'is', 'this', 'that', 'you', 'i', 'of', 'to', 'in', 'it', 'for', 'on', 'with', 'as', 'are', 'was'];
        $polishScore = 0;
        $englishScore = 0;
        foreach ($polishWords as $word) {
            if (preg_match('/\b' . preg_quote($word, '/') . '\b/u', $content)) {
                $polishScore++;
            }
        }
        foreach ($englishWords as $word) {
            if (preg_match('/\b' . preg_quote($word, '/') . '\b/u', $content)) {
                $englishScore++;
            }
        }
        $containsPolishSigns = preg_match('/[ąćęłńóśźż]/u', $content);
        if ($containsPolishSigns) {
            $polishScore += 2;
        }
        $containsOtherLanguage = true;
        if (
            ($polishScore >= $englishScore && $polishScore >= 3)
            || ($englishScore > $polishScore && $englishScore >= 3)
        ) {
            $containsOtherLanguage = false;
        }
        return $containsOtherLanguage;
    }

    function sendToVirusTotal($filePath)
    {
        if (!file_exists($filePath)) {
            throw new Exception('File not found: ' . $filePath);
        }
        $url = 'https://www.virustotal.com/api/v3/files';
        $file = curl_file_create($filePath);
        $postFields = ['file' => $file];
        $headers = ['x-apikey: ' . $this->virusTotalApiKey];
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $postFields,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if (curl_errno($ch)) {
            throw new Exception('cURL error: ' . curl_error($ch));
        }
        curl_close($ch);
        if ($httpCode !== 200 && $httpCode !== 202) {
            throw new Exception('VirusTotal API returned HTTP ' . $httpCode . ': ' . $response);
        }
        $data = json_decode($response, true);
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $data['data']['links']['self'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
        ]);
        $response = curl_exec($ch);
        $data = json_decode($response, true);
        $stats = $data['data']['attributes']['stats'];
        $isVirus = false;
        if ($stats['malicious'] > 3 || $stats['suspicious']) {
            $isVirus = true;
        }
        return $isVirus;
    }

    public function checkAttachments()
    {
        foreach ($this->attachments as $attachment) {
            if (!$this->isMimeTypeMatchingExtension($attachment)) {
                $this->score -= self::MIME_TYPE_NOT_MATCH;
            }
            if ($this->isExecutable($attachment)) {
                $this->score -= self::EXECUTABLE_FILE;
            }
            if ($this->sendToVirusTotal($attachment)) {
                $this->score -= self::CONTAINS_VIRUS;
            }
        }
    }

    private function isMimeTypeMatchingExtension($filePath)
    {
        if (!file_exists($filePath)) {
            throw new Exception('File not found: ' . $filePath);
        }
        $fileInfo = finfo_open(FILEINFO_MIME_TYPE);
        $realMimeType = finfo_file($fileInfo, $filePath);
        finfo_close($fileInfo);
        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $mimeMap = [
            'jpg' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png' => 'image/png',
            'gif' => 'image/gif',
            'pdf' => 'application/pdf',
            'zip' => 'application/zip',
            'txt' => 'text/plain',
            'html' => 'text/html',
            'htm' => 'text/html',
            'doc' => 'application/msword',
            'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls' => 'application/vnd.ms-excel',
            'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'csv' => 'text/csv',
            'mp4' => 'video/mp4',
            'mp3' => 'audio/mpeg',
            'webp' => 'image/webp'
        ];
        if (!isset($mimeMap[$extension])) {
            throw new Exception('Unknown file extension: .' . $extension);
        }
        return $mimeMap[$extension] === $realMimeType;
    }

    private function isExecutable($filePath)
    {
        return is_file($filePath) && is_executable($filePath);
    }
}
