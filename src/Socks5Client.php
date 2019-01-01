<?php

namespace TimeFinger;

class Socks5Client implements ConstantInterface
{
    use HeaderTrait;

    public $method;
    
    private $proxy_client = null;

    private $chan = null;

    private $auth = false;

    public function __construct($configs)
    {
        // 必须在server之前，因为如果在server之后的话，onReceive中取不到$this->proxy_client
        $this->proxy_client = new \Swoole\Client(SWOOLE_SOCK_TCP);
        $server_host = $configs['server_host'] ?? '127.0.0.1';
        $server_port = $configs['server_port'] ?? 9503;
        if (!$this->proxy_client->connect($server_host, $server_port, self::CONNECT_TIMEOUT)) {
            exit('remote connection error[' . $this->proxy_client->errCode . ']: ' . socket_strerror($this->proxy_client->errCode) . PHP_EOL);
        }
        
        $local_host = $configs['local_host'] ?? '0.0.0.0';
        $local_port = $configs['local_port'] ?? 1081;
        $this->configs = $configs;
        $server = new \Swoole\Server($local_host, $local_port);
        $server->on('start', array($this, 'onStart'));
        $server->on('connect', array($this, 'onConnect'));
        $server->on('receive', array($this, 'onReceive'));
        $server->on('close', array($this, 'onClose'));
        $server->start();
    }

    public function onStart($server)
    {
        echo 'started', "\n";
        // onStart时与代理服务器建立链接
        $methods = [
            self::METHOD_NOAUTH,
            self::METHOD_GSSAPI,
            self::METHOD_USERPASS,
        ];
        $this->proxy_client->send(pack('C*', self::VER, count($methods), ...$methods));
        $data = $this->proxy_client->recv();
        list($ver, $method) = str_split(bin2hex($data), 2);
        if (hexdec($ver) != self::VER || !in_array(hexdec($method), $methods)) {
            echo '版本号或验证方法错误', "\n";
            $this->proxy_client->close();
            $server->stop();    // 调用close会提示 Cannot close connection in master process.
        }

        if ($method == self::METHOD_USERPASS) {
            $uname = $this->configs['server_user'] ?? '';
            $passwd = $this->configs['server_pass'] ?? '';

            $send = [
                self::VER,
                strlen($uname),
            ];
            $send = array_merge($send, unpack('c*', $uname));
            $send[] = strlen($passwd);
            $send = array_merge($send, unpack('c*', $passwd));
            $this->proxy_client->send(pack('C*', ...$send));
            $data = $this->proxy_client->recv();
            list($ver, $status) = str_split(bin2hex($data), 2);
            if (hexdec($ver) != self::VER || hexdec($status) != self::AUTH_STATUS_SUCC) {
                echo '用户名或密码错误', "\n";
                $this->proxy_client->close();
                $server->stop();    // 调用close会提示 Cannot close connection in master process.
            }
        }
    }

    public function onConnect($serv, $fd)
    {
        echo "connection open: {$fd}", PHP_EOL;
    }

    public function onReceive($server, $fd, $from_id, $data)
    {
        if (!$this->auth) {
            // 拼接认证所需要的数据并发送认证数据
            $send = [
                self::VER,
                self::CMD_CONNECT,
                self::COMM_RSV
            ];
            $host = $this->getHost($data);
            $port = $this->getPort($data);
            $ipv4_reg = '/^(\d{1,3}\.){3}\d{1,3}$/';
            $ipv6_reg = "/^([a-fAA-F0-9]{4}\:){7}[a-fAA-F0-9]{4}$/";
            if (preg_match($ipv4_reg, $host)) {
                $send[] = self::COMM_ATYPE_IPV4;
            } elseif (preg_match($ipv6_reg, $host)) {
                $send[] = self::COMM_ATYPE_IPV6;
            } elseif (!empty($host)) {
                $send[] = self::COMM_ATYPE_DOMAIN;
                $send[] = strlen($host);
            } else {
                $server->close($fd);
                exit('host不能为空' . PHP_EOL);
            }
            $host_str_arr = str_split($host);
            foreach ($host_str_arr as $char) {
                $send[] = ord($char);
            }
            $port_arr = str_split(str_pad(dechex($port), 4, 0, STR_PAD_LEFT), 2);
            foreach ($port_arr as &$item) {
                $item = hexdec($item);
            }
            $send = array_merge($send, $port_arr);
            $this->proxy_client->send(pack('C*', ...$send));
            $this->proxy_client->recv();    // 必须把数据接收后，才算完成认证，才能进行下面的发送请求数据
            $this->auth = true;
        }

        // 认证完成后，发送请求头数据
        $this->proxy_client->send($data);
        // 接收响应数据并返回给客户端
        $recv = $this->proxy_client->recv();
        $server->send($fd, $recv);
    }

    public function onClose($server, $fd)
    {
        echo "connection close: {$fd}", PHP_EOL;
    }
}
