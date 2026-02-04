<?php

namespace app\controller;

use app\BaseController;
use Exception;
use app\utils\CheckUtils;
use think\facade\Db;
use think\facade\View;
use think\facade\Cache;
use app\service\OptimizeService;
use app\service\CertTaskService;
use app\service\ExpireNoticeService;
use app\service\ScheduleService;

class System extends BaseController
{
    public function set()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $params = input('post.');
        if (isset($params['mail_type']) && isset($params['mail_name2']) && $params['mail_type'] > 0) {
            $params['mail_name'] = $params['mail_name2'];
            unset($params['mail_name2']);
        }
        foreach ($params as $key => $value) {
            if (empty($key)) {
                continue;
            }
            config_set($key, $value);
        }
        Cache::delete('configs');
        return json(['code' => 0, 'msg' => 'succ']);
    }

    public function loginset()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        return View::fetch();
    }

    public function noticeset()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        return View::fetch();
    }

    public function proxyset()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        return View::fetch();
    }

    public function proxylist()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        return View::fetch();
    }

    public function proxy_data()
    {
        if (!checkPermission(2)) return json(['total' => 0, 'rows' => []]);
        $kw = input('post.kw', null, 'trim');
        $active = input('post.active', null);
        $offset = input('post.offset/d', 0);
        $limit = input('post.limit/d', 15);

        $select = Db::name('proxy');
        if (!empty($kw)) {
            $select->whereLike('name|proxy_server|remark', '%' . $kw . '%');
        }
        if (!isNullOrEmpty($active)) {
            $select->where('active', intval($active));
        }
        $total = $select->count();
        $rows = $select->order('id', 'desc')->limit($offset, $limit)->select()->toArray();
        foreach ($rows as &$row) {
            $row['addtimestr'] = !empty($row['addtime']) ? date('Y-m-d H:i:s', intval($row['addtime'])) : '';
            $row['proxy_addr'] = $row['proxy_server'] . ':' . $row['proxy_port'];
        }
        return json(['total' => $total, 'rows' => $rows]);
    }

    public function proxyform()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $action = input('param.action');
        $info = null;
        if ($action == 'edit') {
            $id = input('get.id/d');
            $info = Db::name('proxy')->where('id', $id)->find();
            if (empty($info)) return $this->alert('error', '代理不存在');
        }
        View::assign('info', $info);
        View::assign('action', $action);
        return View::fetch();
    }

    public function proxy_op()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $action = input('param.action');

        if ($action == 'add') {
            $task = [
                'name' => input('post.name', null, 'trim'),
                'proxy_type' => input('post.proxy_type', 'sock5', 'trim'),
                'proxy_server' => input('post.proxy_server', null, 'trim'),
                'proxy_port' => input('post.proxy_port/d'),
                'proxy_user' => input('post.proxy_user', null, 'trim'),
                'proxy_pwd' => input('post.proxy_pwd', null, 'trim'),
                'remark' => input('post.remark', null, 'trim'),
                'active' => input('post.active/d', 1),
                'addtime' => time(),
            ];
            if (empty($task['name']) || empty($task['proxy_server']) || empty($task['proxy_port'])) {
                return json(['code' => -1, 'msg' => '必填项不能为空']);
            }
            if ($task['proxy_type'] != 'sock5' && $task['proxy_type'] != 'sock5h') {
                return json(['code' => -1, 'msg' => '代理协议不支持']);
            }
            if (Db::name('proxy')->where('name', $task['name'])->find()) {
                return json(['code' => -1, 'msg' => '代理名称已存在']);
            }
            Db::name('proxy')->insert($task);
            return json(['code' => 0, 'msg' => '添加成功']);
        } elseif ($action == 'edit') {
            $id = input('post.id/d');
            $row = Db::name('proxy')->where('id', $id)->find();
            if (!$row) return json(['code' => -1, 'msg' => '代理不存在']);

            $task = [
                'name' => input('post.name', null, 'trim'),
                'proxy_type' => input('post.proxy_type', 'sock5', 'trim'),
                'proxy_server' => input('post.proxy_server', null, 'trim'),
                'proxy_port' => input('post.proxy_port/d'),
                'proxy_user' => input('post.proxy_user', null, 'trim'),
                'proxy_pwd' => input('post.proxy_pwd', null, 'trim'),
                'remark' => input('post.remark', null, 'trim'),
                'active' => input('post.active/d', 1),
            ];
            if (empty($task['name']) || empty($task['proxy_server']) || empty($task['proxy_port'])) {
                return json(['code' => -1, 'msg' => '必填项不能为空']);
            }
            if ($task['proxy_type'] != 'sock5' && $task['proxy_type'] != 'sock5h') {
                return json(['code' => -1, 'msg' => '代理协议不支持']);
            }
            if (Db::name('proxy')->where('name', $task['name'])->where('id', '<>', $id)->find()) {
                return json(['code' => -1, 'msg' => '代理名称已存在']);
            }
            Db::name('proxy')->where('id', $id)->update($task);
            return json(['code' => 0, 'msg' => '修改成功']);
        } elseif ($action == 'setactive') {
            $id = input('post.id/d');
            $active = input('post.active/d', 0);
            Db::name('proxy')->where('id', $id)->update(['active' => $active]);
            return json(['code' => 0, 'msg' => '设置成功']);
        } elseif ($action == 'del') {
            $id = input('post.id/d');
            Db::name('proxy')->where('id', $id)->delete();
            return json(['code' => 0, 'msg' => '删除成功']);
        } else {
            return json(['code' => -1, 'msg' => '参数错误']);
        }
    }

    public function proxy_pool_test()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $id = input('post.id/d');
        $test_host = input('post.test_host', null, 'trim');
        $test_port = input('post.test_port/d', 443);
        $timeout = input('post.timeout/d', 3);
        if (empty($test_host) || empty($test_port)) {
            return json(['code' => -1, 'msg' => '参数不能为空']);
        }
        if ($timeout < 1) $timeout = 1;
        if ($timeout > 30) $timeout = 30;

        if (!empty($id)) {
            $proxy = Db::name('proxy')->where('id', $id)->find();
            if (empty($proxy)) return json(['code' => -1, 'msg' => '代理不存在']);
            if (intval($proxy['active']) != 1) return json(['code' => -1, 'msg' => '代理未启用']);
        } else {
            $proxy = input('post.proxy');
            if (!is_array($proxy)) return json(['code' => -1, 'msg' => '代理参数错误']);
            $proxy = [
                'proxy_type' => $proxy['proxy_type'] ?? 'sock5',
                'proxy_server' => trim($proxy['proxy_server'] ?? ''),
                'proxy_port' => intval($proxy['proxy_port'] ?? 0),
                'proxy_user' => trim($proxy['proxy_user'] ?? ''),
                'proxy_pwd' => trim($proxy['proxy_pwd'] ?? ''),
                'active' => 1,
            ];
            if (empty($proxy['proxy_server']) || empty($proxy['proxy_port'])) {
                return json(['code' => -1, 'msg' => '代理服务器和端口不能为空']);
            }
        }

        $useRemoteDns = $proxy['proxy_type'] == 'sock5h';
        $result = CheckUtils::tcpViaSocks5($test_host, $test_port, $timeout, $proxy, $useRemoteDns);
        if ($result['status']) {
            return json(['code' => 0, 'msg' => '连接成功', 'usetime' => $result['usetime']]);
        }
        return json(['code' => -1, 'msg' => $result['errmsg'] ?: '连接失败', 'usetime' => $result['usetime']]);
    }

    public function mailtest()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $mail_name = config_get('mail_recv') ? config_get('mail_recv') : config_get('mail_name');
        if (empty($mail_name)) return json(['code' => -1, 'msg' => '您还未设置邮箱！']);
        $result = \app\utils\MsgNotice::send_mail($mail_name, '邮件发送测试。', '这是一封测试邮件！<br/><br/>来自：' . $this->request->root(true));
        if ($result === true) {
            return json(['code' => 0, 'msg' => '邮件发送成功！']);
        } else {
            return json(['code' => -1, 'msg' => '邮件发送失败！' . $result]);
        }
    }

    public function tgbottest()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $tgbot_token = config_get('tgbot_token');
        $tgbot_chatid = config_get('tgbot_chatid');
        if (empty($tgbot_token) || empty($tgbot_chatid)) return json(['code' => -1, 'msg' => '请先保存设置']);
        $content = "<strong>消息发送测试</strong>\n\n这是一封测试消息！\n\n来自：" . $this->request->root(true);
        $result = \app\utils\MsgNotice::send_telegram_bot($content);
        if ($result === true) {
            return json(['code' => 0, 'msg' => '消息发送成功！']);
        } else {
            return json(['code' => -1, 'msg' => '消息发送失败！' . $result]);
        }
    }

    public function webhooktest()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $webhook_url = config_get('webhook_url');
        if (empty($webhook_url)) return json(['code' => -1, 'msg' => '请先保存设置']);
        $content = "这是一封测试消息！\n来自：" . $this->request->root(true);
        $result = \app\utils\MsgNotice::send_webhook('消息发送测试', $content);
        if ($result === true) {
            return json(['code' => 0, 'msg' => '消息发送成功！']);
        } else {
            return json(['code' => -1, 'msg' => '消息发送失败！' . $result]);
        }
    }

    public function proxytest()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        $proxy_server = input('post.proxy_server', '', 'trim');
        $proxy_port = input('post.proxy_port/d', 0);
        $proxy_user = input('post.proxy_user', '', 'trim');
        $proxy_pwd = input('post.proxy_pwd', '', 'trim');
        $proxy_type = input('post.proxy_type', 'http', 'trim');
        try {
            check_proxy('https://dl.amh.sh/ip.htm', $proxy_server, $proxy_port, $proxy_type, $proxy_user, $proxy_pwd);
        } catch (Exception $e) {
            try {
                check_proxy('https://myip.ipip.net/', $proxy_server, $proxy_port, $proxy_type, $proxy_user, $proxy_pwd);
            } catch (Exception $e) {
                return json(['code' => -1, 'msg' => $e->getMessage()]);
            }
        }
        return json(['code' => 0]);
    }

    public function cronset()
    {
        if (!checkPermission(2)) return $this->alert('error', '无权限');
        if (config_get('cron_key') === null) {
            config_set('cron_key', random(10));
            Cache::delete('configs');
        }
        View::assign('is_user_www', isset($_SERVER['USER']) && $_SERVER['USER'] == 'www');
        View::assign('siteurl', request()->root(true));
        return View::fetch();
    }

    public function cron()
    {
        if (function_exists("set_time_limit")) {
            @set_time_limit(0);
        }
        if (function_exists("ignore_user_abort")) {
            @ignore_user_abort(true);
        }
        if (isset($_SERVER['HTTP_USER_AGENT']) && str_contains($_SERVER['HTTP_USER_AGENT'], 'Baiduspider')) exit;
        $key = input('get.key', '');
        $cron_key = config_get('cron_key');
        if (config_get('cron_type', '0') != '1' || empty($cron_key)) exit('未开启当前方式');
        if ($key != $cron_key) exit('访问密钥错误');

        (new ScheduleService())->execute();
        $res = (new OptimizeService())->execute();
        if (!$res) {
            (new CertTaskService())->execute();
            (new ExpireNoticeService())->task();
        }
        echo 'success!';
    }
}