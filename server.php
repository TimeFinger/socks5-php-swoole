<?php

namespace TimeFinger;

class Socks5Server
{
    const STAGE_INIT = 0;
    const STAGE_ADDRESSING = 1;
    const STAGE_REQUEST = 2;

    const METHOD_NOAUTH = 0x00;
    const METHOD_GSSAPI = 0x01;
    const METHOD_USERPASS = 0x02;
    const METHOD_INNA = [0x03, 0x7F];
    const METHOD_PRIVATE = [0x80, 0xFE];
    const METHOD_NOACCEPT = 0xFF;

    const VER = 0x05;

    public $method;

    public $clients = [];

    private $remote_client = null;

    public function __construct($method = 0x00)
    {
        $this->method = $method;
        $server = new \Swoole\Server("0.0.0.0", 9503);
        $server->on('connect', array($this, 'onConnect'));
        $server->on('receive', array($this, 'onReceive'));
        $server->on('close', array($this, 'onClose'));
        $server->start();
    }

    public function onConnect($serv, $fd)
    {
        $this->clients[$fd] = [
            'stage' =>  self::STAGE_INIT,
        ];
        echo "connection open: {$fd}", PHP_EOL;
    }

    public function onReceive($server, $fd, $from_id, $data)
    {
        if ($this->clients[$fd]['stage'] == self::STAGE_INIT) {
            echo 'init...', PHP_EOL;
            $data_hex_header = unpack('H2VER/H2NMETHODS', $data);
            $nmethods = $data_hex_header['NMETHODS'];
            $data_hex_all = bin2hex($data);
            $data_hex_body = substr($data_hex_all, strlen(implode('', $data_hex_header)));
            $methods = str_split($data_hex_body, 2);
            
            if (!in_array($this->method, $methods)) {
                echo '不支持认证方法\x' . str_pad(dechex($this->method), 2, 0, STR_PAD_LEFT), PHP_EOL;
                $server->close();
            }
            $this->clients[$fd]['stage'] = self::STAGE_ADDRESSING;
            $server->send($fd, pack('C2', self::VER, $this->method));
        } elseif ($this->clients[$fd]['stage'] == self::STAGE_ADDRESSING) {
            echo 'addressing...', PHP_EOL;
            $data_hex_all = bin2hex($data);
            $data_hex_header = unpack('H2VER/H2CMD/H2RSV/H2ATYP', $data);
            $data_hex_body = substr($data_hex_all, strlen(implode('', $data_hex_header)));
            $data_hex_addr = str_split(substr($data_hex_body, 0, -4), 2);
            array_walk($data_hex_addr, function(&$val, $key) {
                $val = hexdec($val);
            });
            $data_addr = implode('.', $data_hex_addr);
            $data_hex_port = substr($data_hex_all, -4);
            $data_port = hexdec($data_hex_port);
            
            $this->remote_client = new \Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
            $local = &$this->clients;
            $this->remote_client->on('connect', function($client) use ($server, $fd, &$local) {
                $server->send($fd, "\x05\x00\x00\x01\x00\x00\x00\x00\x0a\x50");
                $local[$fd]['stage'] = self::STAGE_REQUEST;
            });
            $this->remote_client->on('error', function($client) use ($server, $fd) {
                echo 'remote connection error.', PHP_EOL;
                $server->close($fd);
            });
            $this->remote_client->on('receive', function($cli, $data) use ($server, $fd) {
                // 收到远程目标服务器发回的数据后直接转发给客户端
                $server->send($fd, $data);
                $server->close($fd);
            });
            $this->remote_client->on('close', function($client) use($server, $fd, &$local) {
                echo 'remote connection close.', PHP_EOL;
                $server->close($fd);
            });
            $this->remote_client->connect($data_addr, $data_port);
        } elseif ($this->clients[$fd]['stage'] == self::STAGE_REQUEST) {
            echo 'request...', PHP_EOL;
            // 将客户端的请求转发给远程目标服务器
            $this->remote_client->send($data);
        }
    }

    public function onClose($server, $fd)
    {
        echo "connection close: {$fd}", PHP_EOL;
    }
}

new \TimeFinger\Socks5Server();
