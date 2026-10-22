<?php

// Run with: php -n tests/online-update-disabled.php
namespace think\facade {
    // Capture the application's route declarations without loading the framework.
    class Route
    {
        public static array $rules = [];
        private static string $prefix = '';

        public static function group($prefix, $callback = null)
        {
            if (is_callable($prefix)) { $callback = $prefix; $prefix = ''; }
            $previous = self::$prefix;
            self::$prefix .= $prefix;
            try { $callback(); } finally { self::$prefix = $previous; }
            return new self();
        }
        public static function __callStatic($method, $args)
        {
            if (in_array($method, ['get', 'post', 'any'], true)) {
                self::$rules[strtoupper($method) . ' /' . ltrim(self::$prefix . $args[0], '/')] = $args[1];
            }
            return new self();
        }
        public function middleware($name) { return $this; }
    }
}

namespace {
    spl_autoload_register(function ($class) {
        if (!str_starts_with($class, 'app\\')) return;
        $file = __DIR__ . '/../' . str_replace('\\', '/', $class) . '.php';
        if (is_file($file)) require $file;
    });
    require __DIR__ . '/../route/app.php';

    $tests = [
        'online update endpoints are not registered' => function () {
            foreach (['GET /system/update', 'POST /system/checkupdate', 'POST /system/doupdate'] as $endpoint) {
                if (isset(\think\facade\Route::$rules[$endpoint])) throw new \RuntimeException('Update endpoint remains accessible: ' . $endpoint);
            }
            if (!isset(\think\facade\Route::$rules['GET /system/proxylist'])) throw new \RuntimeException('Proxy management must remain accessible');
        },
        'controller actions cannot invoke online updates through automatic routing' => function () {
            foreach (['update', 'checkupdate', 'doupdate'] as $action) {
                if (method_exists(\app\controller\System::class, $action)) throw new \RuntimeException('Update controller action remains callable: ' . $action);
            }
            foreach (['proxylist', 'proxy_pool_test', 'cron'] as $action) {
                if (!method_exists(\app\controller\System::class, $action)) throw new \RuntimeException('Existing system action was removed: ' . $action);
            }
        },
        'the online update execution service is unavailable' => function () {
            if (class_exists(\app\service\UpdateService::class)) throw new \RuntimeException('Online update execution is still available');
        },
    ];
    $failures = 0;
    foreach ($tests as $name => $test) {
        try { $test(); echo 'PASS ' . $name . "\n"; }
        catch (\Throwable $e) { $failures++; echo 'FAIL ' . $name . ': ' . $e->getMessage() . "\n"; }
    }
    echo count($tests) . ' tests, ' . $failures . " failures\n";
    exit($failures ? 1 : 0);
}
