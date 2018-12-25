<?php
/**
 * 直接测试Socks5Server
 * Socks5 server需要启动
 */
$cli = new Swoole\Http\Client('httpbin.org', 80);
$cli->setHeaders([
    'Host' => "httpbin.org",
    "User-Agent" => 'Chrome/49.0.2587.3',
    'Accept' => 'text/html,application/xhtml+xml,application/xml',
    'Accept-Encoding' => 'gzip',
]);
$cli->set(array(
    'socks5_host'     =>  '127.0.0.1',
    'socks5_port'     =>  9503,
));
$cli->get('/get', function ($cli) {
    echo $cli->body;
    $cli->close();
});
