<?php

namespace TimeFinger;

class Socks5Server implements ConstantInterface
{

    use HeaderTrait;

    public $method;

    public $clients = [];

    // 用户名密码映射数组
    private $user_pass_map = [
    ];

    public function __construct($configs)
    {
        $this->method = $configs['method'] ?? 0x00;
        $server_host = $configs['host'] ?? '0.0.0.0';
        $server_port = $configs['port'] ?? 9503;
        if ($configs['user'] && $configs['pass']) {
            $this->user_pass_map[$configs['user']] = $configs['pass'];
        }

        $server = new \Swoole\Server($server_host, $server_port);
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
                $server->close($fd);
            } else {
                switch ($this->method) {
                    case self::METHOD_NOAUTH:
                        $this->clients[$fd]['stage'] = self::STAGE_ADDRESSING;
                        break;
                    case self::METHOD_GSSAPI:
                        // code..
                        break;
                    case self::METHOD_USERPASS:
                        $this->clients[$fd]['stage'] = self::STAGE_AUTH;
                        break;
                    default:
                        // code..
                        break;
                }
                $server->send($fd, pack('C2', self::VER, $this->method));
            }
        } elseif ($this->clients[$fd]['stage'] == self::STAGE_AUTH) {
            echo 'auth...', PHP_EOL;
            $data_hex_all = bin2hex($data);
            $data_hex_all = str_split($data_hex_all, 2);
            list($ver, $ulen) = $data_hex_all;
            $uname = array_slice($data_hex_all, 2, $ulen);
            foreach ($uname as &$char) {
                $char = hexdec($char);
            }
            $uname = pack('c*', ...$uname);
            $plen = $data_hex_all[2 + $ulen];
            $passwd = array_slice($data_hex_all, '-' . $plen);
            foreach ($passwd as &$char) {
                $char = hexdec($char);
            }
            $passwd = pack('c*', ...$passwd);
            // 检测用户名密码是否正确
            $passwd_right = $this->user_pass_map[$uname] ?? '';
            if (!empty($passwd_right) && $passwd_right == $passwd) {
                $server->send($fd, pack('c2', self::VER, self::AUTH_STATUS_SUCC));
                $this->clients[$fd]['stage'] = self::STAGE_ADDRESSING;
            } else {
                var_dump($passwd_right);
                echo '用户名密码验失败', PHP_EOL;
                $server->send($fd, pack('c2', self::VER, self::AUTH_STATUS_FAILD));
                $server->close($fd);
            }
        } elseif ($this->clients[$fd]['stage'] == self::STAGE_ADDRESSING) {
            echo 'addressing...', PHP_EOL;
            $data_hex_all = bin2hex($data);
            $data_hex_header = unpack('H2VER/H2CMD/H2RSV/H2ATYP', $data);
            $data_hex_body = substr($data_hex_all, strlen(implode('', $data_hex_header)));
            $data_hex_addr = str_split(substr($data_hex_body, 0, -4), 2);
            switch ($data_hex_header['ATYP']) {
                case self::COMM_ATYPE_IPV4:
                    foreach ($data_hex_addr as &$val) {
                        $val = hexdec($val);
                    }
                    $this->dst_addr = implode('.', $data_hex_addr);
                    break;
                case self::COMM_ATYPE_DOMAIN:
                    $addr_len = array_shift($data_hex_addr);
                    foreach ($data_hex_addr as &$val) {
                        $val = chr(hexdec($val));
                    }
                    $this->dst_addr = implode('', $data_hex_addr);
                    break;
                case self::COMM_ATYPE_IPV6:
                    # code...
                    break;
                default:
                    # code...
                    break;
            }
            $data_hex_port = substr($data_hex_all, -4);
            $this->dst_port = hexdec($data_hex_port);
            
            $this->clients[$fd]['remote_client'] = new \Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            if (!$this->clients[$fd]['remote_client']->connect($this->dst_addr, $this->dst_port, self::CONNECT_TIMEOUT)) {
                $server->close($fd);
                exit('remote connection error[' . $this->clients[$fd]['remote_client']->errCode . ']: ' . socket_strerror($this->clients[$fd]['remote_client']->errCode) . PHP_EOL);
            }
            $server->send($fd, pack("C10", self::VER, self::REP_SUCC, self::COMM_RSV, self::COMM_ATYPE_IPV4, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x50));
            $this->clients[$fd]['stage'] = self::STAGE_REQUEST;
        } elseif ($this->clients[$fd]['stage'] == self::STAGE_REQUEST) {
            echo 'request...', PHP_EOL;
            // 将客户端的请求转发给远程目标服务器
            $host = $this->getHost($data);
            $port = $this->getPort($data);
            if ($host != $this->dst_addr || $port != $this->dst_port) {
                $remote_client = new \Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
                if (!$remote_client->connect($host, $port, self::CONNECT_TIMEOUT)) {
                    $server->close($fd);
                    exit('remote connection error[' . $remote_client->errCode . ']: ' . socket_strerror($remote_client->errCode) . PHP_EOL);
                }
            } else {
                $remote_client = $this->clients[$fd]['remote_client'];
            }
            $remote_client->send($data);
            // 将收到远程目标服务器发回的数据后直接转发给客户端
            $server->send($fd, $remote_client->recv());
        }
    }

    public function onClose($server, $fd)
    {
        echo "connection close: {$fd}", PHP_EOL;
    }
}
