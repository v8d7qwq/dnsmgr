<?php

// Run with: php -n tests/tcp-proxy-monitor.php
require __DIR__ . '/support/monitor.php';
require __DIR__ . '/../app/utils/CheckUtils.php';
require __DIR__ . '/../app/utils/MsgNotice.php';
require __DIR__ . '/../app/service/TaskRunner.php';

use app\lib\NewDb;
use app\service\TaskRunner;
use app\utils\CheckUtils;

function config_get($key, $default = null)
{
    return [
        'notice_custom_webhook' => 1,
        'custom_webhook_url' => 'https://notifications.invalid/test',
    ][$key] ?? $default;
}
function convert_second($seconds) { return $seconds . '秒'; }
function getDnsType($value) { return filter_var($value, FILTER_VALIDATE_IP) ? 'A' : 'CNAME'; }
function getMillisecond() { return intval(microtime(true) * 1000); }

function expect($condition, $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function fixture(): array
{
    $store = new tests\Store();
    $task = [
        'id' => 1, 'did' => 1, 'rr' => 'www', 'recordid' => 'record-1',
        'type' => 2, 'main_value' => '192.0.2.1', 'backup_value' => '192.0.2.2',
        'checktype' => 1, 'checkurl' => '', 'tcpport' => 443, 'timeout' => 1,
        'tcp_proxy_id' => 1, 'cycle' => 1, 'status' => 0, 'errcount' => 0,
        'switchtime' => 0, 'recordinfo' => '{"Line":"0","TTL":600}',
        'cdn' => 0, 'cname_flatten' => 0, 'remark' => '',
    ];
    $store->tables = [
        'proxy' => [[
            'id' => 1, 'name' => '测试代理', 'proxy_type' => 'sock5',
            'proxy_server' => '127.0.0.1', 'proxy_port' => closed_port(),
            'proxy_user' => 'user', 'proxy_pwd' => 'secret', 'active' => 1,
        ]],
        'dmtask' => [$task], 'config' => [], 'log' => [], 'dmlog' => [],
        'domain' => [['id' => 1, 'name' => 'example.test', 'type' => 'test', 'config' => '{}']],
    ];
    NewDb::$store = $store;
    return [$store, $task];
}

function closed_port(): int
{
    $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    $port = intval(substr(strrchr(stream_socket_get_name($server, false), ':'), 1));
    fclose($server);
    return $port;
}

function with_proxy(string $mode, callable $run): void
{
    $process = proc_open([PHP_BINARY, '-n', __DIR__ . '/support/socks-server.php', $mode], [
        0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'],
    ], $pipes);
    if (!is_resource($process)) throw new RuntimeException('Unable to start localhost SOCKS fixture');
    try {
        $address = trim(fgets($pipes[1]));
        expect(str_starts_with($address, '127.0.0.1:'), 'SOCKS fixture did not start');
        $port = intval(substr(strrchr($address, ':'), 1));
        $run($port);
    } finally {
        foreach ($pipes as $pipe) fclose($pipe);
        proc_terminate($process);
        proc_close($process);
    }
}

$tests = [];
$tests['closed proxy is classified separately from a target failure'] = function () {
    [$store] = fixture();
    $result = CheckUtils::tcpViaSocks5('192.0.2.1', 443, 1, $store->tables['proxy'][0]);
    expect(!$result['status'] && ($result['proxy_error'] ?? null) === true, 'Proxy connection failure needs proxy_error=true');
};
$tests['proxy failure leaves DNS and target state unchanged and resets confirmation count'] = function () {
    [$store, $task] = fixture();
    $task['errcount'] = 2;
    $store->tables['dmtask'][0] = $task;
    (new TaskRunner())->execute($task);
    expect($store->dnsChanges === [], 'Proxy failure must never modify DNS');
    expect($store->tables['dmtask'][0]['status'] === 0, 'Proxy failure must not mark target down');
    expect($store->tables['dmtask'][0]['errcount'] === 0, 'Unknown target state interrupts consecutive confirmations');
    expect($store->tables['dmlog'] === [], 'Proxy failure must not be logged as a failover');
    expect(count($store->messages) === 1 && str_contains($store->messages[0]['title'], 'TCP代理连接失败'), 'Send a separate proxy failure notification');
    expect(!str_contains($store->messages[0]['content'], 'secret'), 'Never include proxy credentials');
};
$tests['persistent fault is deduplicated across tasks and runner instances'] = function () {
    [$store, $task] = fixture();
    (new TaskRunner())->execute($task);
    $task['id'] = 2;
    $store->tables['dmtask'][] = $task;
    (new TaskRunner())->execute($task);
    (new TaskRunner())->execute($task);
    expect(count($store->messages) === 1, 'Shared proxy fault should generate only one notification');
    expect($store->dnsChanges === [], 'Repeated proxy failures must not cause failover');
};
$tests['proxy recovery sends one recovery notification and a later fault alerts again'] = function () {
    [$store, $task] = fixture();
    (new TaskRunner())->execute($task);
    with_proxy('success', function ($port) use ($store, $task) {
        $store->tables['proxy'][0]['proxy_port'] = $port;
        (new TaskRunner())->execute($task);
    });
    with_proxy('success', function ($port) use ($store, $task) {
        $store->tables['proxy'][0]['proxy_port'] = $port;
        (new TaskRunner())->execute($task);
    });
    expect(count($store->messages) === 2 && str_contains($store->messages[1]['title'], 'TCP代理恢复正常'), 'Send exactly one proxy recovery notification');
    expect(str_contains($store->messages[1]['content'], '异常持续时间'), 'Recovery must describe outage duration');
    expect($store->dnsChanges === [], 'Healthy target after proxy recovery does not cause DNS changes');
    $store->tables['proxy'][0]['proxy_port'] = closed_port();
    (new TaskRunner())->execute($task);
    expect(count($store->messages) === 3, 'A new outage must generate a new alert');
};
$tests['proxy recovery with a refused target still performs normal failover'] = function () {
    [$store, $task] = fixture();
    (new TaskRunner())->execute($task);
    with_proxy('refused', function ($port) use ($store, $task) {
        $store->tables['proxy'][0]['proxy_port'] = $port;
        (new TaskRunner())->execute($task);
    });
    expect(count($store->messages) === 3, 'Expect proxy fault, proxy recovery and target fault notifications');
    expect(str_contains($store->messages[1]['title'], 'TCP代理恢复正常'), 'Target refusal confirms that proxy is reachable');
    expect(count($store->dnsChanges) === 1 && $store->dnsChanges[0][1][3] === '192.0.2.2', 'Refused target must switch to the backup');
};
$tests['proxy outage does not restore an already failed target'] = function () {
    [$store, $task] = fixture();
    $task['status'] = 1;
    $task['errcount'] = 1;
    $store->tables['dmtask'][0] = $task;
    (new TaskRunner())->execute($task);
    expect($store->dnsChanges === [] && $store->tables['dmtask'][0]['status'] === 1, 'Proxy outage must preserve an existing failover');
};
$tests['disabled and deleted proxies do not trigger failover or repeated alerts'] = function () {
    foreach (['disabled', 'deleted'] as $mode) {
        [$store, $task] = fixture();
        if ($mode === 'disabled') $store->tables['proxy'][0]['active'] = 0;
        else $store->tables['proxy'] = [];
        (new TaskRunner())->execute($task);
        (new TaskRunner())->execute($task);
        expect($store->dnsChanges === [] && count($store->messages) === 1, $mode . ' proxy must alert once and preserve DNS');
    }
};
$tests['direct TCP target failures still trigger failover and normal notifications'] = function () {
    [$store, $task] = fixture();
    $task['tcp_proxy_id'] = 0;
    $task['checkurl'] = '127.0.0.1';
    $task['tcpport'] = closed_port();
    $store->tables['dmtask'][0] = $task;
    (new TaskRunner())->execute($task);
    expect(count($store->dnsChanges) === 1 && $store->dnsChanges[0][1][3] === '192.0.2.2', 'Direct TCP detection must retain existing failover');
    expect(count($store->messages) === 1 && str_contains($store->messages[0]['title'], '发生告警'), 'Direct target failure should use the original notification');
    expect($store->tables['config'] === [], 'Direct checks must not create proxy outage state');
};
$tests['target confirmations restart after a proxy outage'] = function () {
    [$store, $task] = fixture();
    $task['cycle'] = 3;
    $task['errcount'] = 3;
    $store->tables['dmtask'][0] = $task;
    (new TaskRunner())->execute($task);
    with_proxy('refused', function ($port) use ($store) {
        $store->tables['proxy'][0]['proxy_port'] = $port;
        (new TaskRunner())->execute($store->tables['dmtask'][0]);
    });
    expect($store->dnsChanges === [] && $store->tables['dmtask'][0]['errcount'] === 1, 'Target failures separated by a proxy outage must not count as consecutive');
};
$tests['target connection timeout through a healthy proxy still triggers failover'] = function () {
    [$store, $task] = fixture();
    with_proxy('connect-timeout', function ($port) use ($store, $task) {
        $store->tables['proxy'][0]['proxy_port'] = $port;
        (new TaskRunner())->execute($task);
    });
    expect(count($store->dnsChanges) === 1 && str_contains($store->messages[0]['title'], '发生告警'), 'A responding proxy waiting for an unresponsive target must retain target failover');
};
foreach (['bad-greeting' => true, 'auth-failed' => true, 'unsupported' => true, 'truncated-connect' => true, 'connect-timeout' => false, 'refused' => false, 'unreachable' => false, 'success' => false] as $mode => $proxyError) {
    $tests['SOCKS classification: ' . $mode] = function () use ($mode, $proxyError) {
        [$store] = fixture();
        with_proxy($mode, function ($port) use ($store, $mode, $proxyError) {
            $proxy = $store->tables['proxy'][0];
            $proxy['proxy_port'] = $port;
            $result = CheckUtils::tcpViaSocks5('192.0.2.1', 443, 1, $proxy);
            expect(($result['proxy_error'] ?? null) === $proxyError, $mode . ': unexpected proxy failure classification');
            expect($result['status'] === ($mode === 'success'), $mode . ': unexpected target result');
        });
    };
}

$failures = 0;
foreach ($tests as $name => $test) {
    try {
        $test();
        echo 'PASS ' . $name . "\n";
    } catch (Throwable $e) {
        $failures++;
        echo 'FAIL ' . $name . ': ' . $e->getMessage() . "\n";
    }
}
echo count($tests) . ' tests, ' . $failures . " failures\n";
exit($failures ? 1 : 0);
