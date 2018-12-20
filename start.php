<?php

if (isset($argv[1])) {
    if ($argv[1] == 'server') {
        require 'server.php';
        new \TimeFinger\Socks5Server();
    } elseif ($argv[1] == 'client') {
        require 'client.php';
        new \TimeFinger\Socks5Client();
    }
}
exit(1);
