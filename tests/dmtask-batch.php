<?php

// Run with: php -n tests/dmtask-batch.php
require __DIR__ . '/../app/utils/DmtaskUtils.php';

use app\utils\DmtaskUtils;

function expect($condition, $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function task(array $override = []): array
{
    return array_merge([
        'id' => 1, 'did' => 1, 'rr' => 'ly.cm', 'recordid' => 'record-1',
        'type' => 2, 'main_value' => '192.0.2.1', 'backup_value' => '192.0.2.2',
        'checktype' => 1, 'checkurl' => '', 'tcpport' => 443, 'frequency' => 5,
        'cycle' => 3, 'timeout' => 2, 'tcp_proxy_id' => 1, 'cdn' => 1, 'cname_flatten' => 1,
    ], $override);
}

$controller = file_get_contents(__DIR__ . '/../app/controller/Dmonitor.php');
$routes = file_get_contents(__DIR__ . '/../route/app.php');

$tests = [
    'single task validation keeps the original rules' => function () {
        $row = task(['timeout' => 6]);
        expect(DmtaskUtils::normalize($row) !== null, 'Timeout greater than frequency must be rejected');
        $row = task(['backup_value' => '192.0.2.1']);
        expect(DmtaskUtils::normalize($row) === '主备地址不能相同', 'Identical main and backup values must be rejected');
        $row = task(['type' => 1, 'checktype' => 2]);
        expect(DmtaskUtils::normalize($row) === null, 'A valid task must pass');
        expect($row['cdn'] === 0 && $row['cname_flatten'] === 0 && $row['tcp_proxy_id'] === 0, 'Switch-only and TCP-only options must be cleared when not applicable');
    },
    'tasks with a specified check IP may share a record' => function () {
        expect(!DmtaskUtils::needDuplicateCheck(task(['checkurl' => '198.51.100.1'])), 'TCP tasks with a check IP must skip the duplicate check');
        expect(DmtaskUtils::needDuplicateCheck(task()), 'TCP tasks without a check IP must be checked for duplicates');
        expect(DmtaskUtils::needDuplicateCheck(task(['checktype' => 2, 'checkurl' => 'https://example.test'])), 'HTTP tasks must be checked for duplicates');
    },
    'editing a task never restores the duplicate check' => function () use ($controller) {
        $start = strpos($controller, "\$action == 'edit'");
        $end = strpos($controller, "\$action == 'batchedit'");
        expect($start !== false && $end > $start, 'Edit branch not found');
        $edit = substr($controller, $start, $end - $start);
        expect(!str_contains($edit, 'needDuplicateCheck') && !str_contains($edit, "where('recordid'"), 'Edit must not reject duplicate records');
    },
    'batch changes ignore blank fields and reject invalid values' => function () {
        [$changes, $error] = DmtaskUtils::batchChanges(['frequency' => '10', 'cycle' => '', 'tcp_proxy_id' => '0', 'ids' => ['1']]);
        expect($error === null && $changes === ['frequency' => 10, 'tcp_proxy_id' => 0], 'Only filled batch fields may be changed');
        expect(DmtaskUtils::batchChanges(['cycle' => ''])[1] !== null, 'An empty batch edit must be rejected');
        expect(DmtaskUtils::batchChanges(['timeout' => '0'])[1] !== null, 'Zero timeout must be rejected');
        expect(DmtaskUtils::batchChanges(['tcpport' => '70000'])[1] !== null, 'Out of range ports must be rejected');
        expect(DmtaskUtils::batchChanges(['frequency' => '-1'])[1] !== null, 'Negative values must be rejected');
    },
    'batch changes only apply to compatible tasks' => function () {
        $changes = ['frequency' => 10, 'cycle' => 4, 'timeout' => 3, 'tcpport' => 8443, 'tcp_proxy_id' => 0];
        [$update] = DmtaskUtils::batchApply(task(), $changes);
        expect($update === $changes, 'A TCP task must accept every batch field');
        [$update] = DmtaskUtils::batchApply(task(['checktype' => 2]), $changes);
        expect(!isset($update['tcpport']) && !isset($update['tcp_proxy_id']) && $update['timeout'] === 3, 'HTTP tasks must keep their TCP settings');
        [$update] = DmtaskUtils::batchApply(task(['checktype' => 0]), $changes);
        expect(!isset($update['timeout']), 'PING tasks have no timeout');
        [$update] = DmtaskUtils::batchApply(task(['type' => 3, 'cycle' => 1]), $changes);
        expect($update === ['frequency' => 10], 'Conditional tasks must keep their record threshold');
    },
    'batch changes cannot make timeout exceed frequency' => function () {
        [$update, $error] = DmtaskUtils::batchApply(task(['timeout' => 5]), ['frequency' => 3]);
        expect($update === [] && str_contains($error, '1'), 'Lowering frequency below the existing timeout must be rejected');
        [, $error] = DmtaskUtils::batchApply(task(['checktype' => 0, 'timeout' => 5]), ['frequency' => 3]);
        expect($error === null, 'PING tasks are not limited by timeout');
    },
    'line names are read from record info' => function () {
        expect(DmtaskUtils::lineName('{"Line":"default","LineName":"默认","TTL":1}') === '默认', 'Line name not parsed');
        expect(DmtaskUtils::lineName('{"Line":"0","TTL":600}') === '0', 'Missing line name must fall back to the line id');
        expect(DmtaskUtils::lineName(null) === '', 'Missing record info must not fail');
    },
    'new task endpoints are routed before the generic action route' => function () use ($routes, $controller) {
        $stats = strpos($routes, "'/dmonitor/task/stats'");
        $generic = strpos($routes, "Route::post('/dmonitor/task/:action'");
        expect($stats !== false && $stats < $generic, 'Stats route must be declared before the generic task action route');
        foreach (["'batchadd'", "'batchedit'", 'function task_stats', "post.orphan"] as $needle) {
            expect(str_contains($controller, $needle), 'Missing controller handler: ' . $needle);
        }
    },
];

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
