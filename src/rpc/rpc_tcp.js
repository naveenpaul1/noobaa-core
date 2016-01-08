'use strict';

module.exports = RpcTcpConnection;

// var _ = require('lodash');
// var P = require('../util/promise');
var net = require('net');
var tls = require('tls');
var url = require('url');
var util = require('util');
var promise_utils = require('../util/promise_utils');
var EventEmitter = require('events').EventEmitter;
var RpcBaseConnection = require('./rpc_base_conn');
var FrameStream = require('../util/frame_stream');
var dbg = require('../util/debug_module')(__filename);

util.inherits(RpcTcpConnection, RpcBaseConnection);

const TCP_FRAME_CONFIG = {
    magic: 'TCPmagic'
};


/**
 *
 * RpcTcpConnection
 *
 */
function RpcTcpConnection(addr_url) {
    RpcBaseConnection.call(this, addr_url);
}

/**
 *
 * connect
 *
 */
RpcTcpConnection.prototype._connect = function() {
    var self = this;
    var connector = (self.url.protocol === 'tls:' ? tls : net);
    self.tcp_conn = connector.connect({
        port: self.url.port,
        host: self.url.hostname,
        // we allow self generated certificates to avoid public CA signing:
        rejectUnauthorized: false,
    }, function() {
        self.emit('connect');
    });
    self._init_tcp();
};

/**
 *
 * close
 *
 */
RpcTcpConnection.prototype._close = function() {
    if (this.tcp_conn) {
        this.tcp_conn.destroy();
    }
};

/**
 *
 * send
 *
 */
RpcTcpConnection.prototype._send = function(msg) {
    return this.frame_stream.send_message(msg);
};

RpcTcpConnection.prototype._init_tcp = function() {
    var self = this;
    var tcp_conn = self.tcp_conn;

    tcp_conn.on('close', function() {
        var closed_err = new Error('TCP CLOSED');
        closed_err.stack = '';
        self.emit('error', closed_err);
    });

    tcp_conn.on('error', function(err) {
        self.emit('error', err);
    });

    tcp_conn.on('timeout', function() {
        var timeout_err = new Error('TCP IDLE TIMEOUT');
        timeout_err.stack = '';
        self.emit('error', timeout_err);
    });

    // FrameStream reads data from the socket and emit framed messages
    self.frame_stream = new FrameStream(tcp_conn, function(msg) {
        self.emit('message', msg);
    }, TCP_FRAME_CONFIG);
};


/**
 *
 * RpcTcpServer
 *
 */
RpcTcpConnection.Server = RpcTcpServer;

util.inherits(RpcTcpServer, EventEmitter);

function RpcTcpServer(tls_options) {
    var self = this;
    EventEmitter.call(self);
    var protocol = (tls_options ? 'tls:' : 'tcp:');

    self.server = tls_options ?
        tls.createServer(tls_options, conn_handler) :
        net.createServer(conn_handler);

    self.server.on('close', function(err) {
        self.emit('error', new Error('TCP SERVER CLOSED'));
    });

    self.server.on('error', function(err) {
        self.emit('error', err);
    });

    function conn_handler(tcp_conn) {
        try {
            // using url.format and then url.parse in order to handle ipv4/ipv6 correctly
            var address = url.format({
                protocol: protocol,
                hostname: tcp_conn.remoteAddress,
                port: tcp_conn.remotePort
            });
            var addr_url = url.parse(address);
            var conn = new RpcTcpConnection(addr_url);
            dbg.log0('TCP ACCEPT CONNECTION', conn.connid + ' ' + conn.url.href);
            conn.tcp_conn = tcp_conn;
            conn._init_tcp();
            conn.emit('connect');
            self.emit('connection', conn);
        } catch (err) {
            dbg.log0('TCP ACCEPT ERROR', address, err.stack || err);
            tcp_conn.destroy();
        }
    }
}

RpcTcpServer.prototype.close = function(err) {
    if (this.closed) return;
    this.closed = true;
    this.emit('close');
    if (this.server) {
        this.server.close();
    }
    this.port = 0;
};

RpcTcpServer.prototype.listen = function(preffered_port) {
    var self = this;
    if (!self.server) {
        throw new Error('TCP SERVER CLOSED');
    }
    if (self.port) {
        return self.port;
    }
    self.server.listen(preffered_port, function() {
        self.port = self.server.address().port;
        self.emit('listening', self.port);
    });
    // will wait for the listening event, but also listen for failures and reject
    return promise_utils.wait_for_event(this, 'listening');
};
