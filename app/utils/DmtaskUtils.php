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
     * 解析记录修改后计算关联策略需要同步的字段
     * $change 可包含 recordid、rr、type、value、old_value、line、linename、ttl，未提供的字段不同步
     * $target 仅在策略已切换到备用且记录值被修改时使用：main 设为新主值，backup 设为新备用值，null 不同步记录值
     * @return array [$update, $notices]
     */
    public static function syncFromRecord(array $task, array $change, ?string $target = null): array
    {
        $update = [];
        $notices = [];
        if (isset($change['recordid']) && strval($change['recordid']) !== '' && $change['recordid'] != $task['recordid']) {
            $update['recordid'] = strval($change['recordid']);
        }
        if (isset($change['rr']) && $change['rr'] !== '' && $change['rr'] != $task['rr']) {
            $update['rr'] = $change['rr'];
        }

        $info = json_decode(strval($task['recordinfo']), true);
        if (!is_array($info)) $info = [];
        $newInfo = $info;
        if (isset($change['line']) && strval($change['line']) !== '') {
            $newInfo['Line'] = strval($change['line']);
            if (isset($change['linename']) && $change['linename'] !== '') $newInfo['LineName'] = $change['linename'];
        }
        if (!empty($change['ttl'])) {
            $newInfo['TTL'] = intval($change['ttl']);
        }
        if ($newInfo != $info) {
            $update['recordinfo'] = json_encode($newInfo, JSON_UNESCAPED_UNICODE);
        }

        if (isset($change['type']) && $change['type'] !== '' && !in_array(strtoupper($change['type']), ['A', 'AAAA', 'CNAME'])) {
            if ($task['active'] == 1) $update['active'] = 0;
            $notices[] = '记录类型改为' . $change['type'] . '，已停止该策略';
            return [$update, $notices];
        }

        if (!isset($change['value']) || $change['value'] === '') {
            return [$update, $notices];
        }
        $value = $change['value'];
        if ($task['type'] != 2 || $task['status'] != 1) {
            // 未切换时记录值即主值
            if ($value != $task['main_value']) {
                if ($task['type'] == 2 && $value == $task['backup_value']) {
                    $notices[] = '新记录值与备用值相同，未同步主值';
                } else {
                    $update['main_value'] = $value;
                }
            }
            return [$update, $notices];
        }

        // 已切换到备用：此时记录值为备用值（或其展平IP），需由用户确认新值的用途
        $changed = isset($change['old_value']) ? $value != $change['old_value'] : ($value != $task['backup_value'] && $value != $task['main_value']);
        if (!$changed) {
            return [$update, $notices];
        }
        if ($target === 'main') {
            if ($value == $task['backup_value']) {
                $notices[] = '新主值与备用值相同，未同步';
            } else {
                if ($value != $task['main_value']) $update['main_value'] = $value;
                $update['status'] = 0;
                $update['errcount'] = 0;
                $notices[] = '已设为新主值，策略恢复为正常状态，主值检测失败时将再次切换';
            }
        } elseif ($target === 'backup') {
            if ($value == $task['main_value']) {
                $notices[] = '新备用值与主值相同，未同步';
            } elseif ($value != $task['backup_value']) {
                $update['backup_value'] = $value;
            }
        } else {
            $notices[] = '策略当前已切换到备用，记录值未同步，请在容灾策略中确认主值和备用值';
        }
        return [$update, $notices];
    }

    /**
     * 解析记录被删除后停止策略，并在 recordinfo 中标记
     */
    public static function markRecordDeleted(array $task): array
    {
        $info = json_decode(strval($task['recordinfo']), true);
        if (!is_array($info)) $info = [];
        $info['RecordDeleted'] = 1;
        return ['active' => 0, 'recordinfo' => json_encode($info, JSON_UNESCAPED_UNICODE)];
    }

    public static function isRecordDeleted($recordinfo): bool
    {
        $info = json_decode(strval($recordinfo), true);
        return is_array($info) && !empty($info['RecordDeleted']);
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
