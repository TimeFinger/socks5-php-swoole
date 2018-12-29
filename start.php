<?php

require './vendor/autoload.php';

if (isset($argv[1])) {
    if ($argv[1] == 'server') {
        $server_configs = [
            'host'  =>  '0.0.0.0',
            'port'  =>  9503,
            'method'=>  0x01,
        ];
        new \TimeFinger\Socks5Server($server_configs);
    } elseif ($argv[1] == 'client') {
        new \TimeFinger\Socks5Client();
    }
}
exit(1);
