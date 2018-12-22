<?php

require './vendor/autoload.php';

if (isset($argv[1])) {
    if ($argv[1] == 'server') {
        new \TimeFinger\Socks5Server();
    } elseif ($argv[1] == 'client') {
        new \TimeFinger\Socks5Client();
    }
}
exit(1);
