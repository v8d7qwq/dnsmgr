<?php

// Run with: php -n tests/dmtask-sync.php
require __DIR__ . '/../app/utils/DmtaskUtils.php';

use app\utils\DmtaskUtils;

function expect($condition, $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function task(array $override = []): array
{
    return array_merge([
        'id' => 7, 'did' => 1, 'rr' => 'ly.cm', 'recordid' => 'record-1',
        'type' => 2, 'main_value' => '192.0.2.1', 'backup_value' => '192.0.2.2',
        'status' => 0, 'errcount' => 0, 'active' => 1,
        'recordinfo' => '{"Line":"default","LineName":"默认","TTL":600}',
    ], $override);
}

$controller = file_get_contents(__DIR__ . '/../app/controller/Domain.php');
$schedule = file_get_contents(__DIR__ . '/../app/service/ScheduleService.php');
$optimize = file_get_contents(__DIR__ . '/../app/service/OptimizeService.php');
$dmonitor = file_get_contents(__DIR__ . '/../app/controller/Dmonitor.php');

$tests = [
    'host record, line and TTL follow the record' => function () {
        [$update, $notices] = DmtaskUtils::syncFromRecord(task(), ['rr' => 'ly.ct', 'line' => '0', 'linename' => '仅DNS', 'ttl' => 1, 'value' => '192.0.2.1']);
        expect($update['rr'] === 'ly.ct', 'Host record must be synchronized');
        expect(json_decode($update['recordinfo'], true) === ['Line' => '0', 'LineName' => '仅DNS', 'TTL' => 1], 'Line and TTL must be synchronized');
        expect(!isset($update['main_value']) && $notices === [], 'An unchanged value must not be rewritten');
    },
    'an unchanged record produces no update' => function () {
        [$update] = DmtaskUtils::syncFromRecord(task(), ['rr' => 'ly.cm', 'line' => 'default', 'linename' => '默认', 'ttl' => 600, 'value' => '192.0.2.1']);
        expect($update === [], 'Nothing must change');
    },
    'a new record id replaces the stored one' => function () {
        [$update] = DmtaskUtils::syncFromRecord(task(), ['recordid' => 'record-2']);
        expect($update === ['recordid' => 'record-2'], 'Recreated records must update the record id');
    },
    'value changes update the main value while not switched' => function () {
        [$update] = DmtaskUtils::syncFromRecord(task(), ['value' => '198.51.100.9']);
        expect($update === ['main_value' => '198.51.100.9'], 'Main value must follow the record');
        [$update] = DmtaskUtils::syncFromRecord(task(['type' => 1, 'status' => 1]), ['value' => '198.51.100.9']);
        expect($update === ['main_value' => '198.51.100.9'], 'Paused records still hold the main value');
        [$update, $notices] = DmtaskUtils::syncFromRecord(task(), ['value' => '192.0.2.2']);
        expect($update === [] && count($notices) === 1, 'Main value must never equal the backup value');
    },
    'switched tasks require an explicit target for value changes' => function () {
        $switched = task(['status' => 1, 'errcount' => 2]);
        [$update, $notices] = DmtaskUtils::syncFromRecord($switched, ['value' => '198.51.100.9', 'old_value' => '192.0.2.2']);
        expect($update === [] && str_contains($notices[0], '未同步'), 'Without a target the value must not be guessed');
        [$update] = DmtaskUtils::syncFromRecord($switched, ['value' => '198.51.100.9', 'old_value' => '192.0.2.2'], 'main');
        expect($update === ['main_value' => '198.51.100.9', 'status' => 0, 'errcount' => 0], 'A new main value resets the task to normal');
        [$update] = DmtaskUtils::syncFromRecord($switched, ['value' => '192.0.2.1', 'old_value' => '192.0.2.2'], 'main');
        expect($update === ['status' => 0, 'errcount' => 0], 'Manually restoring the main value resets the task');
        [$update] = DmtaskUtils::syncFromRecord($switched, ['value' => '198.51.100.9', 'old_value' => '192.0.2.2'], 'backup');
        expect($update === ['backup_value' => '198.51.100.9'], 'A new backup value keeps the switched state');
        [$update, $notices] = DmtaskUtils::syncFromRecord($switched, ['value' => '192.0.2.1', 'old_value' => '192.0.2.2'], 'backup');
        expect($update === [] && count($notices) === 1, 'Backup value must never equal the main value');
    },
    'switched tasks ignore saves that keep the current value' => function () {
        // 展平后记录中保存的是解析出的IP，与备用 CNAME 不同，但并非用户修改
        $switched = task(['status' => 1, 'backup_value' => 'backup.example.test']);
        [$update, $notices] = DmtaskUtils::syncFromRecord($switched, ['value' => '203.0.113.5', 'old_value' => '203.0.113.5', 'ttl' => 300], 'main');
        expect(!isset($update['main_value']) && !isset($update['status']) && $notices === [], 'Unchanged values must not trigger a value sync');
        expect(json_decode($update['recordinfo'], true)['TTL'] === 300, 'Other fields still sync');
    },
    'unsupported record types stop the task' => function () {
        [$update, $notices] = DmtaskUtils::syncFromRecord(task(), ['type' => 'TXT', 'value' => 'v=spf1']);
        expect($update === ['active' => 0] && count($notices) === 1, 'A TXT record cannot be monitored');
        [$update] = DmtaskUtils::syncFromRecord(task(), ['type' => 'cname', 'value' => 'a.example.test']);
        expect($update === ['main_value' => 'a.example.test'], 'CNAME remains supported');
    },
    'deleted records stop the task and are flagged' => function () {
        $update = DmtaskUtils::markRecordDeleted(task());
        expect($update['active'] === 0 && DmtaskUtils::isRecordDeleted($update['recordinfo']), 'Deleted record must be flagged');
        expect(json_decode($update['recordinfo'], true)['Line'] === 'default', 'Existing record info must be kept');
        expect(!DmtaskUtils::isRecordDeleted(task()['recordinfo']) && !DmtaskUtils::isRecordDeleted(null), 'Normal records are not flagged');
    },
    'every record write path synchronizes strategies' => function () use ($controller, $schedule, $optimize) {
        foreach (['record_update', 'record_delete', 'record_batch', 'record_batch_edit', 'record_batch_edit2'] as $method) {
            $start = strpos($controller, 'public function ' . $method . '(');
            expect($start !== false, 'Missing controller method ' . $method);
            $end = strpos($controller, 'public function ', $start + 10);
            expect(str_contains(substr($controller, $start, $end - $start), 'DmtaskSyncService::'), $method . ' must synchronize strategies');
        }
        expect(substr_count($schedule, 'DmtaskSyncService::') >= 2, 'Scheduled switching must synchronize strategies');
        expect(substr_count($optimize, 'DmtaskSyncService::') >= 3, 'Preferred IP updates must synchronize strategies');
    },
    'deleted-record tasks cannot be re-enabled' => function () use ($dmonitor) {
        expect(substr_count($dmonitor, 'isRecordDeleted') >= 2, 'Enabling a task must check for deleted records');
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
