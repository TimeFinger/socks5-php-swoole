<?php

namespace TimeFinger;

class Socks5Server
{
    const VER = 0x05;

    /**
     * 各请求阶段定义
     */
    const STAGE_INIT = 0;
    const STAGE_ADDRESSING = 1;
    const STAGE_REQUEST = 2;

    /**
     * 初始化阶段METHODS定义
     */
    const METHOD_NOAUTH = 0x00;
    const METHOD_GSSAPI = 0x01;
    const METHOD_USERPASS = 0x02;
    const METHOD_INNA = [0x03, 0x7F];
    const METHOD_PRIVATE = [0x80, 0xFE];
    const METHOD_NOACCEPT = 0xFF;

    /**
     * ADDRESSING客户端请求阶段CMD定义
     */
    const CMD_CONNECT = 0x01;
    const CMD_BIND = 0x02;
    const CMD_UDP_ASSOCIATE = 0x03;

    /**
     * 一些公用字段定义
     */
    const COMM_RSV = 0x00;
    const COMM_ATYPE_IPV4 = 0x01;
    const COMM_ATYPE_DOMAIN = 0x03;
    const COMM_ATYPE_IPV6 = 0x04;

    /**
     * ADDRESSING服务端响应阶段REP定义
     */
    const REP_SUCC = 0x00;
    // todo other status


    const CONNECT_TIMEOUT = 10;  // 设置超时时间为10s

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
                $server->send($fd, pack('C2', self::VER, self::METHOD_NOACCEPT));
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
            foreach ($data_hex_addr as &$val) {
                $val = hexdec($val);
            }
            $data_addr = implode('.', $data_hex_addr);
            $data_hex_port = substr($data_hex_all, -4);
            $data_port = hexdec($data_hex_port);
            
            $this->remote_client = new \Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            if (!$this->remote_client->connect($data_addr, $data_port, self::CONNECT_TIMEOUT)) {
                $server->close($fd);
                exit('remote connection error[' . $this->remote_client->errCode . ']: ' . socket_strerror($this->remote_client->errCode) . PHP_EOL);
            }
            $server->send($fd, pack("C10", self::VER, self::REP_SUCC, self::COMM_RSV, self::COMM_ATYPE_IPV4, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x50));
            $this->clients[$fd]['stage'] = self::STAGE_REQUEST;
        } elseif ($this->clients[$fd]['stage'] == self::STAGE_REQUEST) {
            echo 'request...', PHP_EOL;
            // 将客户端的请求转发给远程目标服务器
            $this->remote_client->send($data);
            // 将收到远程目标服务器发回的数据后直接转发给客户端
            $server->send($fd, $this->remote_client->recv());
            $this->remote_client->close();
        }
    }

    public function onClose($server, $fd)
    {
        echo "connection close: {$fd}", PHP_EOL;
    }
}

new \TimeFinger\Socks5Server();
