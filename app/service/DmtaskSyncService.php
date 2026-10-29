<?php

namespace app\service;

use think\facade\Db;
use app\utils\DmtaskUtils;

/**
 * 解析记录变更后同步关联的容灾切换策略
 */
class DmtaskSyncService
{
    private static $fieldNames = [
        'recordid' => '记录ID', 'rr' => '主机记录', 'main_value' => '主值', 'backup_value' => '备用值',
        'recordinfo' => '线路/TTL', 'active' => '运行开关', 'status' => '健康状况', 'errcount' => '确认计数',
    ];

    /**
     * 记录修改后同步，返回 [同步策略数, 提示信息]
     */
    public static function recordUpdated($did, $recordid, array $change, $target = null): array
    {
        if (empty($recordid)) return [0, []];
        $target = in_array($target, ['main', 'backup'], true) ? $target : null;
        $tasks = Db::name('dmtask')->where('did', $did)->where('recordid', $recordid)->select()->toArray();
        $count = 0;
        $notices = [];
        foreach ($tasks as $task) {
            [$update, $taskNotices] = DmtaskUtils::syncFromRecord($task, $change, $target);
            foreach ($taskNotices as $notice) {
                $notices[] = '策略ID ' . $task['id'] . '：' . $notice;
            }
            if (empty($update)) continue;
            Db::name('dmtask')->where('id', $task['id'])->update($update);
            $count++;
            self::log($did, $task, '同步容灾策略', $update, $taskNotices);
        }
        return [$count, $notices];
    }

    /**
     * 记录删除后停止关联策略，返回停止的策略数
     */
    public static function recordDeleted($did, $recordid): int
    {
        if (empty($recordid)) return 0;
        $tasks = Db::name('dmtask')->where('did', $did)->where('recordid', $recordid)->select()->toArray();
        foreach ($tasks as $task) {
            $update = DmtaskUtils::markRecordDeleted($task);
            Db::name('dmtask')->where('id', $task['id'])->update($update);
            self::log($did, $task, '停止容灾策略', [], ['解析记录已删除，策略已停止运行']);
        }
        return count($tasks);
    }

    /**
     * 查询解析记录关联的策略：recordid => ['count' => 策略数, 'switched' => 是否有策略已切换到备用]
     */
    public static function linked($did, array $recordids): array
    {
        $recordids = array_values(array_filter(array_map('strval', $recordids), 'strlen'));
        if (empty($recordids)) return [];
        $rows = Db::name('dmtask')->where('did', $did)->whereIn('recordid', $recordids)->field('recordid,type,status')->select();
        $map = [];
        foreach ($rows as $row) {
            $key = strval($row['recordid']);
            if (!isset($map[$key])) $map[$key] = ['count' => 0, 'switched' => false];
            $map[$key]['count']++;
            if ($row['type'] == 2 && $row['status'] == 1) $map[$key]['switched'] = true;
        }
        return $map;
    }

    /**
     * 拼接同步结果提示，附加在原操作结果后
     */
    public static function message(int $count, array $notices): string
    {
        $msg = $count > 0 ? '，已同步' . $count . '条容灾策略' : '';
        if (!empty($notices)) $msg .= '<br/>' . implode('<br/>', array_map('htmlspecialchars', $notices));
        return $msg;
    }

    private static function log($did, array $task, string $action, array $update, array $notices)
    {
        $fields = [];
        foreach ($update as $key => $value) {
            $fields[] = self::$fieldNames[$key] ?? $key;
        }
        $data = $task['rr'] . ' 策略ID ' . $task['id'];
        if (!empty($fields)) $data .= ' 更新' . implode('、', array_unique($fields));
        if (!empty($notices)) $data .= '（' . implode('；', $notices) . '）';
        if (mb_strlen($data) > 200) $data = mb_substr($data, 0, 200);
        $user = request()->user ?? null;
        Db::name('log')->insert([
            'uid' => is_array($user) ? ($user['id'] ?? 0) : 0,
            'domain' => Db::name('domain')->where('id', $did)->value('name') ?: '',
            'action' => $action,
            'data' => $data,
            'addtime' => date('Y-m-d H:i:s'),
        ]);
    }
}
