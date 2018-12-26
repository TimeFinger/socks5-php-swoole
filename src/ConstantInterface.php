<?php

namespace TimeFinger;

interface ConstantInterface
{
    const VER = 0x05;

    /**
     * 各请求阶段定义
     */
    const STAGE_INIT = 0;
    const STAGE_AUTH = 1;
    const STAGE_ADDRESSING = 2;
    const STAGE_REQUEST = 3;

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
     * auth阶段一些常量定义
     */
    const AUTH_STATUS_SUCC = 0x00;
    const AUTH_STATUS_FAILD = 0x01;

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
}
