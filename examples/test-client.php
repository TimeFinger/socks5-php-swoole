<?php
/**
 * 直接测试Socks5Client
 * Socks5 server和client均要启动
 */
go(function () {
    $cli = new Swoole\Coroutine\Http\Client('httpbin.org', 80);
    $cli->setHeaders([
        'Host' => "httpbin.org",
        "User-Agent" => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip',
    ]);
    $cli->set(array(
        'http_proxy_host'     =>  '127.0.0.1',
        'http_proxy_port'     =>  1081,
    ));
    $cli->get('/get');
    echo $cli->body;
    $cli->close();
});
