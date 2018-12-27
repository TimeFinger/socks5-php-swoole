<?php

namespace TimeFinger;

trait HeaderTrait
{
    private $headers = [];

    public function getHeaders($data)
    {
        $data_lines = explode("\n", trim($data));
        foreach ($data_lines as $key => $line) {
            if ($key > 0) {
                $line_arr = explode(': ', trim($line));
                $this->headers[$line_arr[0]] = $line_arr[1];
            }
        }
        return $this->headers;
    }

    public function getHost($data)
    {
        $headers = $this->getHeaders($data);
        $hosts = explode(':', $headers['Host']);
        return $hosts[0] ?? '';
    }

    public function getPort($data, $default = 80)
    {
        $headers = $this->getHeaders($data);
        $hosts = explode(':', $headers['Host']);
        return $hosts[1] ?? 80;
    }
}
