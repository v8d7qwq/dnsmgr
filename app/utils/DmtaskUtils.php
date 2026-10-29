<?php

namespace app\utils;

/**
 * 容灾切换策略的字段校验与批量修改规则
 */
class DmtaskUtils
{
    // 统计周期内切换（失败+恢复）次数达到阈值视为频繁抖动
    const FLAP_DAYS = 7;
    const FLAP_THRESHOLD = 10;

    // 批量修改允许调整的字段
    const BATCH_FIELDS = ['frequency', 'cycle', 'timeout', 'tcpport', 'tcp_proxy_id'];

    /**
     * 校验并规范化单条策略，返回错误信息，校验通过返回 null
     */
    public static function normalize(array &$task): ?string
    {
        if (empty($task['did']) || empty($task['rr']) || empty($task['recordid']) || empty($task['main_value']) || empty($task['frequency']) || empty($task['cycle'])) {
            return '必填项不能为空';
        }
        if ($task['checktype'] > 0 && $task['timeout'] > $task['frequency']) {
            return '为保障容灾切换任务正常运行，最大超时时间不能大于检测间隔';
        }
        if ($task['type'] == 2 && $task['backup_value'] == $task['main_value']) {
            return '主备地址不能相同';
        }
        if ($task['type'] != 2) {
            $task['cdn'] = 0;
            $task['cname_flatten'] = 0;
        }
        if ($task['checktype'] != 1) {
            $task['tcp_proxy_id'] = 0;
        }
        return null;
    }

    /**
     * 添加策略时是否需要做重复校验：仅未指定检测IP的 PING/TCP 及 HTTP(S) 策略需要
     */
    public static function needDuplicateCheck(array $task): bool
    {
        return $task['checktype'] >= 2 || empty($task['checkurl']);
    }

    /**
     * 从批量修改表单中取出需要修改的字段，留空表示不修改
     * @return array [$changes, $error]
     */
    public static function batchChanges(array $input): array
    {
        $changes = [];
        foreach (self::BATCH_FIELDS as $field) {
            if (!isset($input[$field]) || $input[$field] === '') continue;
            if (!preg_match('/^\d+$/', strval($input[$field]))) {
                return [[], '参数格式错误'];
            }
            $changes[$field] = intval($input[$field]);
        }
        if (empty($changes)) {
            return [[], '请至少填写一项要修改的参数'];
        }
        foreach (['frequency' => '检测间隔', 'cycle' => '确认次数', 'timeout' => '最大超时时间'] as $field => $name) {
            if (isset($changes[$field]) && $changes[$field] < 1) {
                return [[], $name . '不能小于1'];
            }
        }
        if (isset($changes['tcpport']) && ($changes['tcpport'] < 1 || $changes['tcpport'] > 65535)) {
            return [[], 'TCP检测端口范围为1-65535'];
        }
        return [$changes, null];
    }

    /**
     * 计算单条策略实际适用的修改项，不适用的字段会被忽略
     * @return array [$update, $error]
     */
    public static function batchApply(array $task, array $changes): array
    {
        $update = [];
        if (isset($changes['frequency'])) {
            $update['frequency'] = $changes['frequency'];
        }
        // 条件开启解析的 cycle 表示“同域名正常数量”，且不做检测
        if ($task['type'] <= 2) {
            if (isset($changes['cycle'])) {
                $update['cycle'] = $changes['cycle'];
            }
            if (isset($changes['timeout']) && $task['checktype'] > 0) {
                $update['timeout'] = $changes['timeout'];
            }
            if ($task['checktype'] == 1) {
                if (isset($changes['tcpport'])) {
                    $update['tcpport'] = $changes['tcpport'];
                }
                if (isset($changes['tcp_proxy_id'])) {
                    $update['tcp_proxy_id'] = $changes['tcp_proxy_id'];
                }
            }
        }
        $merged = array_merge($task, $update);
        if ($merged['type'] <= 2 && $merged['checktype'] > 0 && $merged['timeout'] > $merged['frequency']) {
            return [[], '策略ID ' . $task['id'] . ' 的最大超时时间将大于检测间隔'];
        }
        return [$update, null];
    }

    /**
     * 从 recordinfo 中取出线路名称
     */
    public static function lineName($recordinfo): string
    {
        $info = json_decode(strval($recordinfo), true);
        if (!is_array($info)) return '';
        return strval($info['LineName'] ?? ($info['Line'] ?? ''));
    }
}
