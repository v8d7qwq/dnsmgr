<?php

namespace app\controller;

use app\BaseController;
use app\utils\DmtaskUtils;
use think\facade\Db;
use think\facade\View;
use think\facade\Cache;

class Dmonitor extends BaseController
{
    public function overview()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $switch_count = Db::name('dmlog')->where('date', '>=', date("Y-m-d H:i:s", strtotime("-1 days")))->count();
        $fail_count = Db::name('dmlog')->where('date', '>=', date("Y-m-d H:i:s", strtotime("-1 days")))->where('action', 1)->count();

        $run_time = config_get('run_time', null, true);
        $run_state = $run_time ? (time() - strtotime($run_time) > 10 ? 0 : 1) : 0;
        View::assign('info', [
            'run_count' => config_get('run_count', null, true) ?? 0,
            'run_time' => $run_time ?? '无',
            'run_state' => $run_state,
            'run_error' => config_get('run_error', null, true),
            'switch_count' => $switch_count,
            'fail_count' => $fail_count,
            'swoole' => extension_loaded('swoole') ? '<font color="green">已安装</font>' : '<font color="red">未安装</font>',
        ]);
        return View::fetch();
    }

    public function task()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        View::assign('proxies', $this->activeProxies());
        return View::fetch();
    }

    private function activeProxies(): array
    {
        if (!Db::query("SHOW TABLES LIKE '" . config('database.connections.mysql.prefix') . "proxy'")) {
            return [];
        }
        return Db::name('proxy')->where('active', 1)->order('id', 'desc')->field('id,name,proxy_type,proxy_server,proxy_port')->select()->toArray();
    }

    public function task_data()
    {
        if (!checkPermission(2)) return json(['total' => 0, 'rows' => []]);
        $type = input('post.type/d', 1);
        $status = input('post.status', null);
        $active = input('post.active', null);
        $flap = input('post.flap/d', 0);
        $group = input('post.group/d', 0);
        $kw = input('post.kw', null, 'trim');
        $offset = input('post.offset/d');
        $limit = input('post.limit/d');
        $sort = input('post.sortName', null, 'trim');
        $orderDir = strtolower(input('post.sortOrder', 'desc')) === 'asc' ? 'asc' : 'desc';
        $since = date('Y-m-d H:i:s', strtotime('-' . DmtaskUtils::FLAP_DAYS . ' days'));

        $select = Db::name('dmtask')->alias('A')->join('domain B', 'A.did = B.id');
        if (!empty($kw)) {
            if ($type == 1) {
                $select->whereLike('rr|B.name', '%' . $kw . '%');
            } elseif ($type == 2) {
                $select->where('recordid', $kw);
            } elseif ($type == 3) {
                $select->where('main_value', $kw);
            } elseif ($type == 4) {
                $select->where('backup_value', $kw);
            } elseif ($type == 5) {
                $select->whereLike('remark', '%' . $kw . '%');
            }
        }
        if (!isNullOrEmpty($status)) {
            $select->where('A.status', intval($status));
        }
        if (!isNullOrEmpty($active)) {
            $select->where('A.active', intval($active));
        }
        if ($flap == 1) {
            $select->whereIn('A.id', $this->flapTaskIds($since) ?: [0]);
        }
        $total = $select->count();
        $allowedSort = ['id' => 'A.id', 'rr' => 'A.rr', 'main_value' => 'A.main_value', 'type' => 'A.type', 'checktype' => 'A.checktype', 'frequency' => 'A.frequency', 'status' => 'A.status', 'active' => 'A.active', 'checktimestr' => 'A.checktime', 'switchtimestr' => 'A.switchtime', 'addtimestr' => 'A.addtime', 'remark' => 'A.remark'];
        if ($sort && isset($allowedSort[$sort])) {
            $select->order($allowedSort[$sort], $orderDir);
        } elseif ($group == 1) {
            // 分组视图：同一主机记录的策略相邻排列
            $select->order('B.name', 'asc')->order('A.rr', 'asc')->order('A.id', 'asc');
        } else {
            $select->order('A.id', 'desc');
        }
        $list = $select->limit($offset, $limit)->field('A.*,B.name domain')->select()->toArray();

        $switchCounts = [];
        $proxyNames = [];
        if (!empty($list)) {
            $logs = Db::name('dmlog')->whereIn('taskid', array_column($list, 'id'))->where('date', '>=', $since)->field('taskid,COUNT(*) num')->group('taskid')->select();
            foreach ($logs as $log) {
                $switchCounts[$log['taskid']] = intval($log['num']);
            }
            $proxyIds = array_values(array_filter(array_unique(array_column($list, 'tcp_proxy_id'))));
            if (!empty($proxyIds)) {
                $proxyNames = Db::name('proxy')->whereIn('id', $proxyIds)->column('name', 'id');
            }
        }

        foreach ($list as &$row) {
            $row['addtimestr'] = date('Y-m-d H:i:s', $row['addtime']);
            $row['checktimestr'] = $row['checktime'] > 0 ? date('Y-m-d H:i:s', $row['checktime']) : '未运行';
            $row['switchtimestr'] = $row['switchtime'] > 0 ? date('Y-m-d H:i:s', $row['switchtime']) : '无';
            $row['linename'] = DmtaskUtils::lineName($row['recordinfo']);
            $row['proxy_name'] = $row['tcp_proxy_id'] > 0 ? ($proxyNames[$row['tcp_proxy_id']] ?? '已删除的代理') : '';
            $row['switch_count'] = $switchCounts[$row['id']] ?? 0;
            $row['flapping'] = $row['switch_count'] >= DmtaskUtils::FLAP_THRESHOLD ? 1 : 0;
        }

        return json(['total' => $total, 'rows' => $list]);
    }

    public function task_stats()
    {
        if (!checkPermission(2)) return json(['code' => -1, 'msg' => '无权限']);
        $since = date('Y-m-d H:i:s', strtotime('-' . DmtaskUtils::FLAP_DAYS . ' days'));
        $prefix = config('database.connections.mysql.prefix');
        $orphan = Db::query("SELECT COUNT(*) num FROM `" . $prefix . "dmlog` WHERE `taskid` NOT IN (SELECT `id` FROM `" . $prefix . "dmtask`)");
        return json(['code' => 0, 'data' => [
            'total' => Db::name('dmtask')->count(),
            'running' => Db::name('dmtask')->where('active', 1)->count(),
            'abnormal' => Db::name('dmtask')->where('status', 1)->count(),
            'inactive' => Db::name('dmtask')->where('active', 0)->count(),
            'flap' => count($this->flapTaskIds($since)),
            'orphan' => intval($orphan[0]['num'] ?? 0),
            'flap_days' => DmtaskUtils::FLAP_DAYS,
            'flap_threshold' => DmtaskUtils::FLAP_THRESHOLD,
        ]]);
    }

    // 统计周期内切换次数达到阈值的策略ID
    private function flapTaskIds($since): array
    {
        return Db::name('dmlog')->alias('L')->join('dmtask T', 'L.taskid = T.id')->where('L.date', '>=', $since)->group('L.taskid')->having('COUNT(*) >= ' . DmtaskUtils::FLAP_THRESHOLD)->column('L.taskid');
    }

    // 读取表单中的策略字段
    private function taskInput(): array
    {
        return [
            'did' => input('post.did/d'),
            'rr' => input('post.rr', null, 'trim'),
            'recordid' => input('post.recordid', null, 'trim'),
            'type' => input('post.type/d'),
            'main_value' => input('post.main_value', null, 'trim'),
            'backup_value' => input('post.backup_value', null, 'trim'),
            'checktype' => input('post.checktype/d'),
            'checkurl' => input('post.checkurl', null, 'trim'),
            'tcpport' => !empty(input('post.tcpport')) ? input('post.tcpport/d') : null,
            'frequency' => input('post.frequency/d'),
            'cycle' => input('post.cycle/d'),
            'timeout' => input('post.timeout/d'),
            'proxy' => input('post.proxy/d'),
            'tcp_proxy_id' => input('post.tcp_proxy_id/d', 0),
            'cdn' => input('post.cdn') == 'true' || input('post.cdn') == '1' ? 1 : 0,
            'cname_flatten' => input('post.cname_flatten') == 'true' || input('post.cname_flatten') == '1' ? 1 : 0,
            'remark' => input('post.remark', null, 'trim'),
            'recordinfo' => input('post.recordinfo', null, 'trim'),
        ];
    }

    // 校验策略字段及所选TCP代理，返回错误信息
    private function checkTask(array &$task): ?string
    {
        $error = DmtaskUtils::normalize($task);
        if ($error) return $error;
        if ($task['checktype'] == 1 && $task['tcp_proxy_id'] > 0) {
            $proxy = Db::name('proxy')->where('id', $task['tcp_proxy_id'])->where('active', 1)->find();
            if (!$proxy) {
                return 'TCP代理不存在或未启用';
            }
        }
        return null;
    }

    public function task_op()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $action = input('param.action');
        if ($action == 'add') {
            $task = $this->taskInput();
            $task['addtime'] = time();
            $task['active'] = 1;

            $error = $this->checkTask($task);
            if ($error) {
                return json(['code' => -1, 'msg' => $error]);
            }
            if (DmtaskUtils::needDuplicateCheck($task)) {
                if (Db::name('dmtask')->where('recordid', $task['recordid'])->find()) {
                    return json(['code' => -1, 'msg' => '当前容灾切换策略已存在']);
                }
            }
            Db::name('dmtask')->insert($task);
            return json(['code' => 0, 'msg' => '添加成功']);
        } elseif ($action == 'batchadd') {
            // 公共参数取自表单，每条解析记录可单独覆盖备用解析记录和指定检测IP
            $records = input('post.records/a', []);
            if (empty($records)) {
                return json(['code' => -1, 'msg' => '请至少勾选一条解析记录']);
            }
            if (count($records) > 100) {
                return json(['code' => -1, 'msg' => '单次最多添加100条策略']);
            }
            $base = $this->taskInput();
            $tasks = [];
            $seen = [];
            foreach ($records as $record) {
                $task = $base;
                $task['rr'] = trim(strval($record['rr'] ?? ''));
                $task['recordid'] = trim(strval($record['recordid'] ?? ''));
                $task['main_value'] = trim(strval($record['main_value'] ?? ''));
                $task['recordinfo'] = trim(strval($record['recordinfo'] ?? ''));
                $backupValue = trim(strval($record['backup_value'] ?? ''));
                if ($backupValue !== '') $task['backup_value'] = $backupValue;
                $checkurl = trim(strval($record['checkurl'] ?? ''));
                if ($checkurl !== '') $task['checkurl'] = $checkurl;
                $task['addtime'] = time();
                $task['active'] = 1;

                $label = $task['rr'] . '（' . $task['main_value'] . '）';
                $error = $this->checkTask($task);
                if ($error) {
                    return json(['code' => -1, 'msg' => $label . '：' . $error]);
                }
                if (DmtaskUtils::needDuplicateCheck($task)) {
                    if (isset($seen[$task['recordid']]) || Db::name('dmtask')->where('recordid', $task['recordid'])->find()) {
                        return json(['code' => -1, 'msg' => $label . '：当前容灾切换策略已存在']);
                    }
                    $seen[$task['recordid']] = true;
                }
                $tasks[] = $task;
            }
            Db::name('dmtask')->insertAll($tasks);
            return json(['code' => 0, 'msg' => '成功添加' . count($tasks) . '个容灾切换策略']);
        } elseif ($action == 'edit') {
            $id = input('post.id/d');
            if (!Db::name('dmtask')->where('id', $id)->find()) {
                return json(['code' => -1, 'msg' => '切换策略不存在']);
            }
            $task = $this->taskInput();

            $error = $this->checkTask($task);
            if ($error) {
                return json(['code' => -1, 'msg' => $error]);
            }
            // 编辑策略不做重复校验，允许更换解析记录或清空指定检测IP。
            Db::name('dmtask')->where('id', $id)->update($task);
            return json(['code' => 0, 'msg' => '修改成功']);
        } elseif ($action == 'batchedit') {
            $ids = array_map('intval', input('post.ids/a', []));
            if (empty($ids)) {
                return json(['code' => -1, 'msg' => '请选择要修改的策略']);
            }
            [$changes, $error] = DmtaskUtils::batchChanges(input('post.'));
            if ($error) {
                return json(['code' => -1, 'msg' => $error]);
            }
            if (!empty($changes['tcp_proxy_id'])) {
                if (!Db::name('proxy')->where('id', $changes['tcp_proxy_id'])->where('active', 1)->find()) {
                    return json(['code' => -1, 'msg' => 'TCP代理不存在或未启用']);
                }
            }
            // 先全部校验，避免部分策略修改成功后中途失败
            $updates = [];
            foreach (Db::name('dmtask')->whereIn('id', $ids)->select()->toArray() as $task) {
                [$update, $error] = DmtaskUtils::batchApply($task, $changes);
                if ($error) {
                    return json(['code' => -1, 'msg' => $error]);
                }
                if (!empty($update)) {
                    $updates[$task['id']] = $update;
                }
            }
            foreach ($updates as $id => $update) {
                Db::name('dmtask')->where('id', $id)->update($update);
            }
            $skipped = count($ids) - count($updates);
            return json(['code' => 0, 'msg' => '成功修改' . count($updates) . '个容灾切换策略' . ($skipped > 0 ? '，' . $skipped . '个策略不适用所填参数已跳过' : '')]);
        } elseif ($action == 'setactive') {
            $id = input('post.id/d');
            $active = input('post.active/d');
            Db::name('dmtask')->where('id', $id)->update(['active' => $active]);
            return json(['code' => 0, 'msg' => '设置成功']);
        } elseif ($action == 'del') {
            $id = input('post.id/d');
            Db::name('dmtask')->where('id', $id)->delete();
            Db::name('dmlog')->where('taskid', $id)->delete();
            return json(['code' => 0, 'msg' => '删除成功']);
        } elseif ($action == 'operation') {
            $ids = input('post.ids');
            $success = 0;
            foreach ($ids as $id) {
                if (input('post.act') == 'delete') {
                    Db::name('dmtask')->where('id', $id)->delete();
                    Db::name('dmlog')->where('taskid', $id)->delete();
                    $success++;
                } elseif (input('post.act') == 'retry') {
                    Db::name('dmtask')->where('id', $id)->update(['checknexttime' => time()]);
                    $success++;
                } elseif (input('post.act') == 'open' || input('post.act') == 'close') {
                    $isauto = input('post.act') == 'open' ? 1 : 0;
                    Db::name('dmtask')->where('id', $id)->update(['active' => $isauto]);
                    $success++;
                }
            }
            return json(['code' => 0, 'msg' => '成功操作' . $success . '个容灾切换策略']);
        } else {
            return json(['code' => -1, 'msg' => '参数错误']);
        }
    }

    public function taskform()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $action = input('param.action');
        $task = null;
        if ($action == 'edit') {
            $id = input('get.id/d');
            $task = Db::name('dmtask')->where('id', $id)->find();
            if (empty($task)) return $this->alert('error', '切换策略不存在');
        } elseif ($action == 'add' && input('get.copy/d') > 0) {
            // 复制策略：沿用参数，解析记录需重新选择
            $task = Db::name('dmtask')->where('id', input('get.copy/d'))->find();
            if (empty($task)) return $this->alert('error', '切换策略不存在');
            $task = array_diff_key($task, array_flip(['id', 'recordid', 'recordinfo', 'main_value', 'status', 'errcount', 'active', 'addtime', 'checktime', 'checknexttime', 'switchtime']));
        }

        $domains = [];
        $domainList = Db::name('domain')->alias('A')->join('account B', 'A.aid = B.id')->field('A.id,A.name,B.type')->select();
        foreach ($domainList as $row) {
            $domains[] = ['id'=>$row['id'], 'name'=>$row['name'], 'type'=>$row['type']];
        }
        View::assign('domains', $domains);

        View::assign('proxies', $this->activeProxies());

        View::assign('info', $task);
        View::assign('action', $action);
        View::assign('support_ping', function_exists('exec') ? '1' : '0');
        return View::fetch();
    }

    public function taskinfo()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $id = input('param.id/d');
        $task = Db::name('dmtask')->where('id', $id)->find();
        if (empty($task)) return $this->alert('error', '切换策略不存在');

        $switch_count = Db::name('dmlog')->where('taskid', $id)->where('date', '>=', date("Y-m-d H:i:s", strtotime("-1 days")))->count();
        $fail_count = Db::name('dmlog')->where('taskid', $id)->where('date', '>=', date("Y-m-d H:i:s", strtotime("-1 days")))->where('action', 1)->count();

        $task['switch_count'] = $switch_count;
        $task['fail_count'] = $fail_count;
        if ($task['type'] == 3) {
            $task['action_name'] = ['未知', '<font color="red">开启解析</font>', '<font color="green">暂停解析</font>'];
        } elseif ($task['type'] == 2) {
            $task['action_name'] = ['未知', '<font color="red">切换备用解析记录</font>', '<font color="green">恢复主解析记录</font>'];
        } else {
            $task['action_name'] = ['未知', '<font color="red">暂停解析</font>', '<font color="green">启用解析</font>'];
        }
        View::assign('info', $task);
        return View::fetch();
    }

    public function tasklog_data()
    {
        if (!checkPermission(2)) return json(['total' => 0, 'rows' => []]);
        $taskid = input('param.id/d');
        $offset = input('post.offset/d');
        $limit = input('post.limit/d');
        $action = input('post.action/d', 0);

        $select = Db::name('dmlog')->where('taskid', $taskid);
        if ($action > 0) {
            $select->where('action', $action);
        }
        $total = $select->count();
        $list = $select->order('id', 'desc')->limit($offset, $limit)->select();

        return json(['total' => $total, 'rows' => $list]);
    }

    public function clean()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        if ($this->request->isPost()) {
            if (input('post.orphan/d') == 1) {
                // 清理已删除策略遗留的切换记录
                $prefix = config('database.connections.mysql.prefix');
                $count = Db::execute("DELETE FROM `" . $prefix . "dmlog` WHERE `taskid` NOT IN (SELECT `id` FROM `" . $prefix . "dmtask`)");
                return json(['code' => 0, 'msg' => '已清理' . $count . '条孤儿切换记录']);
            }
            $days = input('post.days/d');
            if (!$days || $days < 0) return json(['code' => -1, 'msg' => '参数错误']);
            Db::execute("DELETE FROM `" . config('database.connections.mysql.prefix') . "dmlog` WHERE `date`<'" . date("Y-m-d H:i:s", strtotime("-" . $days . " days")) . "'");
            Db::execute("OPTIMIZE TABLE `" . config('database.connections.mysql.prefix') . "dmlog`");
            return json(['code' => 0, 'msg' => '清理成功']);
        }
    }

    public function status()
    {
        $run_time = config_get('run_time', null, true);
        $run_state = $run_time ? (time() - strtotime($run_time) > 10 ? 0 : 1) : 0;
        return $run_state == 1 ? 'ok' : 'error';
    }
}
