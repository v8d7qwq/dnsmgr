<?php

// One real localhost SOCKS5 exchange, controlled by the parent test process.
$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if (!$server) throw new RuntimeException($errstr);
echo stream_socket_get_name($server, false) . "\n";
flush();
$client = stream_socket_accept($server, 10);
if (!$client) exit(1);
stream_set_timeout($client, 2);

function read_bytes($client, $length): string
{
    $data = '';
    while (strlen($data) < $length) {
        $chunk = fread($client, $length - strlen($data));
        if ($chunk === false || $chunk === '') throw new RuntimeException('Incomplete client request');
        $data .= $chunk;
    }
    return $data;
}

$head = read_bytes($client, 2);
read_bytes($client, ord($head[1]));
$mode = $argv[1];
if ($mode === 'bad-greeting') {
    fwrite($client, "\x04\x00");
} elseif ($mode === 'auth-failed') {
    fwrite($client, "\x05\x02");
    $auth = read_bytes($client, 2);
    read_bytes($client, ord($auth[1]));
    $length = ord(read_bytes($client, 1));
    read_bytes($client, $length);
    fwrite($client, "\x01\x01");
} else {
    fwrite($client, "\x05\x00");
    $head = read_bytes($client, 4);
    $length = match (ord($head[3])) {
        1 => 4,
        4 => 16,
        3 => ord(read_bytes($client, 1)),
    };
    read_bytes($client, $length + 2);
    if ($mode === 'connect-timeout') {
        sleep(3);
        fclose($client);
        fclose($server);
        exit;
    }
    $reply = match ($mode) {
        'refused' => 5,
        'unreachable' => 4,
        'unsupported' => 7,
        default => 0,
    };
    $response = "\x05" . chr($reply) . "\x00\x01\x7f\x00\x00\x01\x00\x50";
    if ($mode === 'truncated-connect') $response = substr($response, 0, 4);
    fwrite($client, $response);
}
fclose($client);
fclose($server);
