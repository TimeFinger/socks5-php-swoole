<?php

require './vendor/autoload.php';

if (isset($argv[1])) {
    if ($argv[1] == 'server') {
        $server_configs = [
            'host'  =>  '0.0.0.0',
            'port'  =>  9503,
            'method'=>  0x02,
            'user' =>  'admin',
            'pass'  =>  'abcdef',
        ];
        new \TimeFinger\Socks5Server($server_configs);
    } elseif ($argv[1] == 'client') {
        $client_configs = [
            'server_host'  =>  '127.0.0.1',
            'server_port'  =>  9503,
            'server_user' =>  'admin',
            'server_pass'  =>  'abcdef',
            'local_host'  =>  '0.0.0.0',
            'local_port'  =>  1081,
        ];
        new \TimeFinger\Socks5Client($client_configs);
    }
}
exit(1);
