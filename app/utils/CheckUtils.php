<?php

namespace app\utils;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class CheckUtils
{
    private static function readExact($fp, int $len): string|false
    {
        $data = '';
        while (strlen($data) < $len && !feof($fp)) {
            $chunk = fread($fp, $len - strlen($data));
            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($fp);
                if (!empty($meta['timed_out'])) {
                    return false;
                }
                // 避免死循环
                usleep(1000 * 10);
                continue;
            }
            $data .= $chunk;
        }
        return strlen($data) === $len ? $data : false;
    }

    private static function isValidDomainName(string $host): bool
    {
        $host = trim($host);
        if ($host === '') return false;
        if (str_ends_with($host, '.')) $host = substr($host, 0, -1);
        // 允许带端点的普通域名；长度限制按常见规则
        if (strlen($host) > 253) return false;
        return (bool)preg_match('/^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)(\\.[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$/', $host);
    }

    public static function curl($url, $timeout, $ip = null, $proxy = false)
    {
        $status = true;
        $errmsg = null;
        $start = microtime(true);

        $urlarr = parse_url($url);
        if (!$urlarr) {
            return ['status' => false, 'errmsg' => 'Invalid URL', 'usetime' => 0];
        }
        if (str_starts_with($urlarr['host'], '[') && str_ends_with($urlarr['host'], ']')) {
            $urlarr['host'] = substr($urlarr['host'], 1, -1);
        }
        if (!empty($ip) && !filter_var($urlarr['host'], FILTER_VALIDATE_IP)) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                $ip = gethostbyname($ip);
            }
            if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
                $port = $urlarr['port'] ?? ($urlarr['scheme'] == 'https' ? 443 : 80);
                $resolve = $urlarr['host'] . ':' . $port . ':' . $ip;
            }
        }

        $options = [
            'timeout' => $timeout,
            'connect_timeout' => $timeout,
            'verify' => false,
            'headers' => [
                'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36'
            ],
            'http_errors' => false // 不抛出异常
        ];
        // 处理解析
        if (!empty($resolve)) {
            $options['curl'] = [
                CURLOPT_DNS_USE_GLOBAL_CACHE => false,
                CURLOPT_RESOLVE => [$resolve]
            ];
        }
        // 处理代理
        if ($proxy) {
            $proxy_server = config_get('proxy_server');
            $proxy_port = intval(config_get('proxy_port'));
            $proxy_userpwd = config_get('proxy_user').':'.config_get('proxy_pwd');
            $proxy_type = config_get('proxy_type');

            if (!empty($proxy_server) && !empty($proxy_port)) {
                match ($proxy_type) {
                    'https' => $proxy_string = 'https://',
                    'sock4' => $proxy_string = 'socks4://',
                    'sock5' => $proxy_string = 'socks5://',
                    'sock5h' => $proxy_string = 'socks5h://',
                    default => $proxy_string = 'http://',
                };

                if ($proxy_userpwd != ':') {
                    $proxy_string .= $proxy_userpwd . '@';
                }

                $proxy_string .= $proxy_server . ':' . $proxy_port;
                $options['proxy'] = $proxy_string;
            }
        }

        try {
            $client = new Client();
            $response = $client->request('GET', $url, $options);
            $httpcode = $response->getStatusCode();

            if ($httpcode < 200 || $httpcode >= 400) {
                $status = false;
                $errmsg = 'http_code=' . $httpcode;
            }
        } catch (GuzzleException $e) {
            $status = false;
            $errmsg = guzzle_error($e);
        }

        $usetime = round((microtime(true) - $start) * 1000);
        return ['status' => $status, 'errmsg' => $errmsg, 'usetime' => $usetime];
    }

    public static function tcp($target, $ip, $port, $timeout)
    {
        if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) $target = $ip;
        if (str_ends_with($target, '.')) $target = substr($target, 0, -1);
        if (!filter_var($target, FILTER_VALIDATE_IP) && checkDomain($target)) {
            $target = gethostbyname($target);
            if (!$target) return ['status' => false, 'errmsg' => 'DNS resolve failed', 'usetime' => 0];
        }
        if (filter_var($target, FILTER_VALIDATE_IP) && str_contains($target, ':')) {
            $target = '['.$target.']';
        }
        $starttime = getMillisecond();
        $fp = @fsockopen($target, $port, $errCode, $errStr, $timeout);
        if ($fp) {
            $status = true;
            fclose($fp);
        } else {
            $status = false;
        }
        $endtime = getMillisecond();
        $usetime = $endtime - $starttime;
        return ['status' => $status, 'errmsg' => $errStr, 'usetime' => $usetime];
    }

    /**
     * 通过 SOCKS5 / SOCKS5H 代理进行 TCP CONNECT 探测
     * $proxyRow 需要字段：proxy_type(sock5|sock5h), proxy_server, proxy_port, proxy_user, proxy_pwd
     */
    public static function tcpViaSocks5($destHostOrIp, $destPort, $timeout, $proxyRow, $useRemoteDns = false)
    {
        $start = microtime(true);
        $errmsg = null;

        $destHostOrIp = trim(strval($destHostOrIp));
        if (str_ends_with($destHostOrIp, '.')) $destHostOrIp = substr($destHostOrIp, 0, -1);
        $destPort = intval($destPort);
        $timeout = intval($timeout);

        if ($destHostOrIp === '' || $destPort < 1 || $destPort > 65535) {
            return ['status' => false, 'errmsg' => 'Invalid target', 'usetime' => 0];
        }
        if ($timeout < 1) $timeout = 1;

        $proxyServer = trim(strval($proxyRow['proxy_server'] ?? ''));
        $proxyPort = intval($proxyRow['proxy_port'] ?? 0);
        $proxyUser = strval($proxyRow['proxy_user'] ?? '');
        $proxyPwd = strval($proxyRow['proxy_pwd'] ?? '');
        if ($proxyServer === '' || $proxyPort < 1 || $proxyPort > 65535) {
            return ['status' => false, 'errmsg' => 'Invalid proxy address', 'usetime' => 0];
        }

        $errno = 0;
        $errstr = '';
        $fp = @stream_socket_client('tcp://' . $proxyServer . ':' . $proxyPort, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT);
        if (!$fp) {
            $usetime = round((microtime(true) - $start) * 1000);
            return ['status' => false, 'errmsg' => 'Proxy connect failed: ' . ($errstr ?: $errno), 'usetime' => $usetime];
        }
        stream_set_timeout($fp, $timeout);

        try {
            // 1) greeting
            $methods = ["\x00"]; // no-auth
            $hasAuth = ($proxyUser !== '' || $proxyPwd !== '');
            if ($hasAuth) $methods[] = "\x02"; // username/password
            $greeting = "\x05" . chr(count($methods)) . implode('', $methods);
            if (fwrite($fp, $greeting) === false) {
                throw new \Exception('SOCKS5 write greeting failed');
            }
            $resp = self::readExact($fp, 2);
            if ($resp === false || strlen($resp) != 2) {
                throw new \Exception('SOCKS5 greeting timeout');
            }
            $ver = ord($resp[0]);
            $method = ord($resp[1]);
            if ($ver !== 0x05) {
                throw new \Exception('SOCKS version invalid');
            }
            if ($method === 0xFF) {
                throw new \Exception('SOCKS auth method not accepted');
            }

            // 2) username/password auth (RFC1929)
            if ($method === 0x02) {
                $u = $proxyUser;
                $p = $proxyPwd;
                if (strlen($u) > 255) $u = substr($u, 0, 255);
                if (strlen($p) > 255) $p = substr($p, 0, 255);
                $authReq = "\x01" . chr(strlen($u)) . $u . chr(strlen($p)) . $p;
                if (fwrite($fp, $authReq) === false) {
                    throw new \Exception('SOCKS auth write failed');
                }
                $authResp = self::readExact($fp, 2);
                if ($authResp === false || strlen($authResp) != 2) {
                    throw new \Exception('SOCKS auth timeout');
                }
                $authVer = ord($authResp[0]);
                $authStatus = ord($authResp[1]);
                if ($authVer !== 0x01 || $authStatus !== 0x00) {
                    throw new \Exception('SOCKS auth failed');
                }
            } elseif ($method !== 0x00) {
                throw new \Exception('SOCKS auth method unsupported');
            }

            // 3) build connect request
            $atyp = null;
            $addrBin = '';

            if (filter_var($destHostOrIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $atyp = 0x01;
                $addrBin = inet_pton($destHostOrIp);
            } elseif (filter_var($destHostOrIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $atyp = 0x04;
                $addrBin = inet_pton($destHostOrIp);
            } else {
                // domain
                if (!$useRemoteDns) {
                    // sock5: 尽量本地解析成 IPv4
                    if (!self::isValidDomainName($destHostOrIp)) {
                        throw new \Exception('Invalid domain');
                    }
                    $resolved = gethostbyname($destHostOrIp);
                    if (!$resolved || $resolved === $destHostOrIp) {
                        throw new \Exception('DNS resolve failed');
                    }
                    $atyp = 0x01;
                    $addrBin = inet_pton($resolved);
                } else {
                    // sock5h: 交给代理端解析
                    if (!self::isValidDomainName($destHostOrIp)) {
                        throw new \Exception('Invalid domain');
                    }
                    $atyp = 0x03;
                    if (strlen($destHostOrIp) > 255) {
                        throw new \Exception('Domain too long');
                    }
                    $addrBin = chr(strlen($destHostOrIp)) . $destHostOrIp;
                }
            }
            if ($addrBin === false || $addrBin === '') {
                throw new \Exception('Target address invalid');
            }
            $req = "\x05" . "\x01" . "\x00" . chr($atyp) . $addrBin . pack('n', $destPort);
            if (fwrite($fp, $req) === false) {
                throw new \Exception('SOCKS connect write failed');
            }

            // 4) read connect response
            $head = self::readExact($fp, 4);
            if ($head === false || strlen($head) != 4) {
                throw new \Exception('SOCKS connect timeout');
            }
            $ver = ord($head[0]);
            $rep = ord($head[1]);
            $atyp2 = ord($head[3]);
            if ($ver !== 0x05) {
                throw new \Exception('SOCKS connect response invalid');
            }
            if ($rep !== 0x00) {
                $repMsg = match ($rep) {
                    0x01 => 'general failure',
                    0x02 => 'connection not allowed',
                    0x03 => 'network unreachable',
                    0x04 => 'host unreachable',
                    0x05 => 'connection refused',
                    0x06 => 'TTL expired',
                    0x07 => 'command not supported',
                    0x08 => 'address type not supported',
                    default => 'unknown error',
                };
                throw new \Exception('SOCKS connect failed: ' . $repMsg);
            }
            // consume BND.ADDR + BND.PORT
            if ($atyp2 === 0x01) {
                self::readExact($fp, 4);
            } elseif ($atyp2 === 0x04) {
                self::readExact($fp, 16);
            } elseif ($atyp2 === 0x03) {
                $l = self::readExact($fp, 1);
                if ($l !== false) {
                    $len = ord($l[0]);
                    if ($len > 0) self::readExact($fp, $len);
                }
            }
            self::readExact($fp, 2);

            fclose($fp);
            $usetime = round((microtime(true) - $start) * 1000);
            return ['status' => true, 'errmsg' => null, 'usetime' => $usetime];
        } catch (\Throwable $e) {
            $errmsg = $e->getMessage();
            try { fclose($fp); } catch (\Throwable $e2) {}
            $usetime = round((microtime(true) - $start) * 1000);
            return ['status' => false, 'errmsg' => $errmsg, 'usetime' => $usetime];
        }
    }

    public static function ping($target, $ip)
    {
        if (!function_exists('exec')) return ['status' => false, 'errmsg' => 'exec函数不可用', 'usetime' => 0];
        if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) $target = $ip;
        if (str_ends_with($target, '.')) $target = substr($target, 0, -1);
        if (!filter_var($target, FILTER_VALIDATE_IP) && checkDomain($target)) {
            $target = gethostbyname($target);
            if (!$target) return ['status' => false, 'errmsg' => 'DNS resolve failed', 'usetime' => 0];
        }
        if (!filter_var($target, FILTER_VALIDATE_IP)) {
            return ['status' => false, 'errmsg' => 'Invalid IP address', 'usetime' => 0];
        }
        $timeout = 1;
        if (str_contains($target, ':')) {
            exec('ping -6 -c 1 -w '.$timeout.' '.$target, $output, $return_var);
        } else {
            exec('ping -c 1 -w '.$timeout.' '.$target, $output, $return_var);
        }
        if (!empty($output[1])) {
            if (strpos($output[1], '毫秒') !== false) {
                $usetime = getSubstr($output[1], '时间=', ' 毫秒');
            } else {
                $usetime = getSubstr($output[1], 'time=', ' ms');
            }
        }
        $usetime = !empty($usetime) ? round(trim($usetime)) : 0;
        $errmsg = null;
        if ($return_var !== 0) {
            $usetime = $usetime == 0 ? $timeout * 1000 : $usetime;
            $errmsg = 'ping timeout';
        }
        return ['status' => $return_var === 0, 'errmsg' => $errmsg, 'usetime' => $usetime];
    }
}
