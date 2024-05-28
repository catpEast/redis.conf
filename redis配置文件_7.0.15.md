redis.conf 详解，基于Redis 7.0.15
> 因为版本改动，配置项、默认值跟其他版本会有少许不同，请使用 Redis 之前仔细核对

> 能力有限，一些不懂的地方进行了简单翻译，还请见谅

### INCLUDES
#### include
```bash
# Include one or more other config files here.  This is useful if you
# have a standard template that goes to all Redis servers but also need
# to customize a few per-server settings.  Include files can include
# other files, so use this wisely.
#
# Note that option "include" won't be rewritten by command "CONFIG REWRITE"
# from admin or Redis Sentinel. Since Redis always uses the last processed
# line as value of a configuration directive, you'd better put includes
# at the beginning of this file to avoid overwriting config change at runtime.
#
# If instead you are interested in using includes to override configuration
# options, it is better to use include as the last line.
#
# Included paths may contain wildcards. All files matching the wildcards will
# be included in alphabetical order.
# Note that if an include path contains a wildcards but no files match it when
# the server is started, the include statement will be ignored and no error will
# be emitted.  It is safe, therefore, to include wildcard files from empty
# directories.
#
# include /path/to/local.conf
# include /path/to/other.conf
# include /path/to/fragments/*.conf
```
include 配置可添加额外的配置文件，支持通配符，且该配置项不会被CONFIG REWRITE指令重写，无默认值
> redis.conf 中如果有相同值，后面的会覆盖前面的，如果想使用include来覆盖前面的配置项，可以将该配置放在最后

### MODULES
#### loadmodule
```bash
# Load modules at startup. If the server is not able to load modules
# it will abort. It is possible to use multiple loadmodule directives.
#
# loadmodule /path/to/my_module.so
# loadmodule /path/to/other_module.so
```
loadmodule 配置可加载外部模块来扩展 Redis 的能力，无默认值
### NETWORK
#### bind
```bash
# By default, if no "bind" configuration directive is specified, Redis listens
# for connections from all available network interfaces on the host machine.
# It is possible to listen to just one or multiple selected interfaces using
# the "bind" configuration directive, followed by one or more IP addresses.
# Each address can be prefixed by "-", which means that redis will not fail to
# start if the address is not available. Being not available only refers to
# addresses that does not correspond to any network interface. Addresses that
# are already in use will always fail, and unsupported protocols will always BE
# silently skipped.
#
# Examples:
#
# bind 192.168.1.100 10.0.0.1     # listens on two specific IPv4 addresses
# bind 127.0.0.1 ::1              # listens on loopback IPv4 and IPv6
# bind * -::*                     # like the default, all available interfaces
#
# ~~~ WARNING ~~~ If the computer running Redis is directly exposed to the
# internet, binding to all the interfaces is dangerous and will expose the
# instance to everybody on the internet. So by default we uncomment the
# following bind directive, that will force Redis to listen only on the
# IPv4 and IPv6 (if available) loopback interface addresses (this means Redis
# will only be able to accept client connections from the same host that it is
# running on).
#
# IF YOU ARE SURE YOU WANT YOUR INSTANCE TO LISTEN TO ALL THE INTERFACES
# COMMENT OUT THE FOLLOWING LINE.
#
# You will also need to set a password unless you explicitly disable protected
# mode.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
bind 127.0.0.1 -::1
```
bind 配置监听的网卡接口，默认127.0.0.1 -::1
> 如果没有配置bind，Redis将监听所有可用网卡接口。可用“-”作为前缀，即如果监听的地址不可用，Redis不会启动失败。如果Redis直接暴露在公网上，监听所有网卡是非常危险的，默认只监听本地IP
> 示例如下：
> - bind 192.168.1.100 10.0.0.1     # 指定监听两个IP地址
> - bind 127.0.0.1 ::1            		 # 监听IPv4和IPv6本地回环地址
> - bind * -::*                     		 # 与默认值一样，所有网卡接口都被监听

#### bind-source-addr
```bash
# By default, outgoing connections (from replica to master, from Sentinel to
# instances, cluster bus, etc.) are not bound to a specific local address. In
# most cases, this means the operating system will handle that based on routing
# and the interface through which the connection goes out.
#
# Using bind-source-addr it is possible to configure a specific address to bind
# to, which may also affect how the connection gets routed.
# 
# Example:
#
# bind-source-addr 10.0.0.1
```
在多网卡接口/多IP环境中，bind-source-addr 配置Redis作为客户端时，使用哪个网卡接口进行出站连接，无默认值
> Redis实例既是服务端又是客户端
> - 作为服务端：处理来自用户的请求
> - 作为客户端：在主从复制、哨兵模式、集群模式中作为客户端

#### protected-mode
```bash
# Protected mode is a layer of security protection, in order to avoid that
# Redis instances left open on the internet are accessed and exploited.
#
# When protected mode is on and the default user has no password, the server
# only accepts local connections from the IPv4 address (127.0.0.1), IPv6 address
# (::1) or Unix domain sockets.
#
# By default protected mode is enabled. You should disable it only if
# you are sure you want clients from other hosts to connect to Redis
# even if no authentication is configured.
protected-mode yes
```
protected-mode 配置保护模式是否开启，默认yes，即当没有配置密码时，Redis只接收本地回环地址或unix domain socket(IPC 本机进程间通信)的客户端连接
#### enable-protected-configs
#### enable-debug-command
#### enable-module-command
```bash
# Redis uses default hardened security configuration directives to reduce the
# attack surface on innocent users. Therefore, several sensitive configuration
# directives are immutable, and some potentially-dangerous commands are blocked.
#
# Configuration directives that control files that Redis writes to (e.g., 'dir'
# and 'dbfilename') and that aren't usually modified during runtime
# are protected by making them immutable.
#
# Commands that can increase the attack surface of Redis and that aren't usually
# called by users are blocked by default.
#
# These can be exposed to either all connections or just local ones by setting
# each of the configs listed below to either of these values:
#
# no    - Block for any connection (remain immutable)
# yes   - Allow for any connection (no protection)
# local - Allow only for local connections. Ones originating from the
#         IPv4 address (127.0.0.1), IPv6 address (::1) or Unix domain sockets.
#
# enable-protected-configs no
# enable-debug-command no
# enable-module-command no
```
Redis的安全机制，在运行时会保护一些敏感配置不被改变，阻止一些危险指令：

- enable-protected-configs：运行时是否可以修改 dbfilename 和 dir 等配置项，默认为no
- enable-debug-command：运行时是否可以执行debug命令，默认为no
- enable-module-command：运行时是否可以执行module命令，默认为no

有如下三种选项：

- no - 任何连接都不允许
- yes - 任何连接都允许
- local - 仅允许本地连接
#### port
```bash
# Accept connections on the specified port, default is 6379 (IANA #815344).
# If port 0 is specified Redis will not listen on a TCP socket.
port 6379
```
port 配置Redis端口号，默认6379
#### tcp-backlog 
```bash
# TCP listen() backlog.
#
# In high requests-per-second environments you need a high backlog in order
# to avoid slow clients connection issues. Note that the Linux kernel
# will silently truncate it to the value of /proc/sys/net/core/somaxconn so
# make sure to raise both the value of somaxconn and tcp_max_syn_backlog
# in order to get the desired effect.
tcp-backlog 511
```
tcp-backlog 配置Linux系统中Redis已完成TCP三次握手的连接的队列长度，默认511
> 注意，该值如果大于somaxconn，Linux内核将默认地将其截断为somaxconn
> 查看somaxconn指令：cat /proc/sys/net/core/somaxconn

#### unixsocket
#### unixsocketperm
```bash
# Unix socket.
#
# Specify the path for the Unix socket that will be used to listen for
# incoming connections. There is no default, so Redis will not listen
# on a unix socket when not specified.
#
# unixsocket /run/redis.sock
# unixsocketperm 700
```
unixsocket 和 unixsocketperm 配置Redis在本机进程间通信访问的unix socket文件位置和权限，无默认值
> 当Redis和应用在同一台机器上时，可以使用进程间通信，性能会提高很多

#### timeout
```bash
# Close the connection after a client is idle for N seconds (0 to disable)
timeout 0
```
timeout 配置Redis关闭空闲超过一定时间的客户端连接，默认0
> 0 表示禁用，即服务端不会主动关闭客户端连接

#### tcp-keepalive
```bash
# TCP keepalive.
#
# If non-zero, use SO_KEEPALIVE to send TCP ACKs to clients in absence
# of communication. This is useful for two reasons:

# 1) Detect dead peers.
# 2) Force network equipment in the middle to consider the connection to be
#    alive.
#
# On Linux, the specified value (in seconds) is the period used to send ACKs.
# Note that to close the connection the double of the time is needed.
# On other kernels the period depends on the kernel configuration.
#
# A reasonable value for this option is 300 seconds, which is the new
# Redis default starting with Redis 3.2.1.
tcp-keepalive 300
```
tcp-keepalive 配置TCP探测频率，默认300秒探测一次
> Redis 配置文件中的 tcp-keepalive 参数用于控制Linux系统中的 TCP keepalive 选项。这是一个网络层的设置，旨在检测和维护空闲的 TCP 连接，避免连接长期处于非活动状态而被网络设备（如路由器、防火墙）意外关闭。

#### socket-mark-id
```bash
# Apply OS-specific mechanism to mark the listening socket with the specified
# ID, to support advanced routing and filtering capabilities.
#
# On Linux, the ID represents a connection mark.
# On FreeBSD, the ID represents a socket cookie ID.
# On OpenBSD, the ID represents a route table ID.
#
# The default value is 0, which implies no marking is required.
# 
# socket-mark-id 0
```
socket-mark-id配置指定的ID来标记socket，以支持高级路由和过滤功能，无默认值
### TLS/SSL
从 Redis 6开始，Redis 支持 SSL/TLS 作为一个可选特性，需要在编译时启用
参考链接：[https://redis.io/docs/management/security/encryption/](https://redis.io/docs/management/security/encryption/)
![image.png](https://cdn.nlark.com/yuque/0/2024/png/42775905/1711346012739-86ad7ac7-000d-4237-84fc-22eb8430d5b0.png#averageHue=%23fefefe&clientId=u710a29bc-5ce8-4&from=paste&height=399&id=uac61f386&originHeight=532&originWidth=731&originalType=binary&ratio=1&rotation=0&showTitle=false&size=49379&status=done&style=none&taskId=uff708f7f-1b80-4f89-a000-bb0af30ee26&title=&width=548)
#### port
#### tls-port
```bash
# By default, TLS/SSL is disabled. To enable it, the "tls-port" configuration
# directive can be used to define TLS-listening ports. To enable TLS on the
# default port, use:

# port 0
# tls-port 6379
```
tls-port 配置 Redis 的 TLS 监听端口，用于加密通信
> Redis 默认监听端口为 6379，若启用 TLS 监听端口，需要先禁用默认的非加密端口，即设置 port 为 0 

#### tls-cert-file
#### tls-key-file
```bash
# Configure a X.509 certificate and private key to use for authenticating the
# server to connected clients, masters or cluster peers.  These files should be
# PEM formatted.
#
# tls-cert-file redis.crt
# tls-key-file redis.key
```
tls-cert-file 配置服务端 TLS 证书文件
tls-key-file 配置服务端 TLS 私钥文件
#### tls-key-file-pass
```bash
# If the key file is encrypted using a passphrase, it can be included here
# as well.
#
# tls-key-file-pass secret
```
tls-key-file-pass 配置用于保护 TLS私钥 的密码，如果私钥是加密的，需要提供密码来解密
#### tls-client-cert-file
#### tls-client-key-file
```bash
# Normally Redis uses the same certificate for both server functions (accepting
# connections) and client functions (replicating from a master, establishing
# cluster bus connections, etc.).

# Sometimes certificates are issued with attributes that designate them as
# client-only or server-only certificates. In that case it may be desired to use
# different certificates for incoming (server) and outgoing (client)
# connections. To do that, use the following directives:
#
# tls-client-cert-file client.crt
# tls-client-key-file client.key
```
tls-client-cert-file 配置客户端认证所需的证书文件路径，用于客户端身份验证
tls-client-key-file 配置客户端认证所需的私钥文件路径，用于客户端身份验证
#### tls-client-key-file-pass
```bash
# If the key file is encrypted using a passphrase, it can be included here
# as well.
#
# tls-client-key-file-pass secret
```
tls-client-key-file-pass 配置用于保护客户端私钥的密码，如果客户端私钥是加密的，需要提供密码来解密
#### tls-dh-params-file
```bash
# Configure a DH parameters file to enable Diffie-Hellman (DH) key exchange,
# required by older versions of OpenSSL (<3.0). Newer versions do not require
# this configuration and recommend against it.
#
# tls-dh-params-file redis.dh
```
tls-dh-params-file 配置 TLS 连接的 Diffie-Hellman 参数文件路径，DH参数用于安全密钥交换
#### tls-ca-cert-file
#### tls-ca-cert-dir
```bash
# Configure a CA certificate(s) bundle or directory to authenticate TLS/SSL
# clients and peers.  Redis requires an explicit configuration of at least one
# of these, and will not implicitly use the system wide configuration.
#
# tls-ca-cert-file ca.crt
# tls-ca-cert-dir /etc/ssl/certs
```
tls-ca-cert-file 配置CA证书文件路径
tls-ca-cert-dir 配置CA证书文件夹
#### tls-auth-clients
#### tls-auth-clients
```bash
# By default, clients (including replica servers) on a TLS port are required
# to authenticate using valid client side certificates.

# If "no" is specified, client certificates are not required and not accepted.
# If "optional" is specified, client certificates are accepted and must be
# valid if provided, but are not required.
#
# tls-auth-clients no
# tls-auth-clients optional
```
tls-auth-clients 否要求客户端提供证书以进行身份验证
#### tls-replication
```bash
# By default, a Redis replica does not attempt to establish a TLS connection
# with its master.
#
# Use the following directive to enable TLS on replication links.
#
# tls-replication yes
```
tls-replication 配置是否在主从复制中使用TLS
#### tls-protocols
```bash
# By default, only TLSv1.2 and TLSv1.3 are enabled and it is highly recommended
# that older formally deprecated versions are kept disabled to reduce the attack surface.
# You can explicitly specify TLS versions to support.
# Allowed values are case insensitive and include "TLSv1", "TLSv1.1", "TLSv1.2",
# "TLSv1.3" (OpenSSL >= 1.1.1) or any combination.
# To enable only TLSv1.2 and TLSv1.3, use:
#
# tls-protocols "TLSv1.2 TLSv1.3"
```
tls-protocols 配置允许的TLS协议版本列表，可以选择多个版本，使用逗号分隔
#### tls-ciphers
```bash
# Configure allowed ciphers.  See the ciphers(1ssl) manpage for more information
# about the syntax of this string.
#
# Note: this configuration applies only to <= TLSv1.2.
#
# tls-ciphers DEFAULT:!MEDIUM
```
tls-ciphers 配置允许的TLS加密套件列表，以逗号分隔，用于TLS 1.2及以下版本
#### tls-ciphersuites
```bash
# Configure allowed TLSv1.3 ciphersuites.  See the ciphers(1ssl) manpage for more
# information about the syntax of this string, and specifically for TLSv1.3
# ciphersuites.
#
# tls-ciphersuites TLS_CHACHA20_POLY1305_SHA256
```
tls-ciphersuites 配置TLS 1.3加密套件列表，以逗号分隔
#### tls-prefer-server-ciphers
```bash
# When choosing a cipher, use the server's preference instead of the client
# preference. By default, the server follows the client's preference.
# 
# tls-prefer-server-ciphers yes
```
tls-prefer-server-ciphers 配置是否优先使用服务器的加密套件顺序，而不是客户端的顺序
#### tls-session-caching
```bash
# By default, TLS session caching is enabled to allow faster and less expensive
# reconnections by clients that support it. Use the following directive to disable
# caching.
#
# tls-session-caching no
```
tls-session-caching 配置是否启用TLS会话缓存，以提高重复连接的性能
#### tls-session-cache-size
```bash
# Change the default number of TLS sessions cached. A zero value sets the cache
# to unlimited size. The default size is 20480.
#
# tls-session-cache-size 5000
```
tls-session-cache-size 配置TLS会话缓存的大小
#### tls-session-cache-timeout
```bash
# Change the default timeout of cached TLS sessions. The default timeout is 300
# seconds.
#
# tls-session-cache-timeout 60
```
tls-session-cache-timeout 配置TLS会话缓存的超时时间（以秒为单位）
### GENERAL
#### daemonize
```bash
# By default Redis does not run as a daemon. Use 'yes' if you need it.
# Note that Redis will write a pid file in /var/run/redis.pid when daemonized.
# When Redis is supervised by upstart or systemd, this parameter has no impact.
daemonize no
```
daemonize 配置是否后台运行Redis，默认no
#### supervised
```bash
# If you run Redis from upstart or systemd, Redis can interact with your
# supervision tree. Options:
#   supervised no      - no supervision interaction
#   supervised upstart - signal upstart by putting Redis into SIGSTOP mode
#                        requires "expect stop" in your upstart job config
#   supervised systemd - signal systemd by writing READY=1 to $NOTIFY_SOCKET
#                        on startup, and updating Redis status on a regular
#                        basis.
#   supervised auto    - detect upstart or systemd method based on
#                        UPSTART_JOB or NOTIFY_SOCKET environment variables
# Note: these supervision methods only signal "process is ready."
#       They do not enable continuous pings back to your supervisor.
#
# The default is "no". To run under upstart/systemd, you can simply uncomment
# the line below:
#
# supervised auto
```
supervised 配置Redis是否应该在受控环境（如 systemd、upstart 或其他进程管理工具）中运行，从而实现更可靠的管理和监控，默认为no
#### pidfile
```bash
# If a pid file is specified, Redis writes it where specified at startup
# and removes it at exit.
#
# When the server runs non daemonized, no pid file is created if none is
# specified in the configuration. When the server is daemonized, the pid file
# is used even if not specified, defaulting to "/var/run/redis.pid".
#
# Creating a pid file is best effort: if Redis is not able to create it
# nothing bad happens, the server will start and run normally.
#
# Note that on modern Linux systems "/run/redis.pid" is more conforming
# and should be used instead.
pidfile /var/run/redis_6379.pid
```
pidfile 配置Redis以后台运行时生成的pid文件位置，默认 /var/run/redis_6379.pid
#### loglevel
```bash
# Specify the server verbosity level.
# This can be one of:
# debug (a lot of information, useful for development/testing)
# verbose (many rarely useful info, but not a mess like the debug level)
# notice (moderately verbose, what you want in production probably)
# warning (only very important / critical messages are logged)
loglevel notice
```
loglevel 配置日志级别，默认notice
> 日志级别，Redis 总共支持四个级别：debug、verbose、notice、warning
> - debug:会打印生成大量信息，适用于开发、测试阶段
> - verbose:包含很多不太有用的信息，但是不像debug级别那么混乱
> - notice:适度冗长，适用于生产环境
> - warning:仅记录非常重要、关键的警告消息

#### logfile
```bash
# Specify the log file name. Also the empty string can be used to force
# Redis to log on the standard output. Note that if you use standard
# output for logging but daemonize, logs will be sent to /dev/null
logfile ""
```
logfile 配置日志文件名称，默认空字符串，即日志会打印到标准输出设备，后台运行的Redis的标准输出是/dev/null
#### syslog-enabled
#### syslog-ident
#### syslog-facility
```bash
# To enable logging to the system logger, just set 'syslog-enabled' to yes,
# and optionally update the other syslog parameters to suit your needs.
# syslog-enabled no

# Specify the syslog identity.
# syslog-ident redis

# Specify the syslog facility. Must be USER or between LOCAL0-LOCAL7.
# syslog-facility local0
```

- syslog-enabled 配置是否将 Redis 日志发送到 syslog，默认为no
- syslog-ident 配置 Redis 在 syslog 中的标识符，有助于区分来自不同服务的日志信息，默认为redis
- syslog-facility 指定 syslog 设施，syslog 设施用于将日志信息分类到不同的日志文件或日志流中。常见的设施包括 local0 到 local7，默认local0
> 要查看 Redis 发送到 syslog 的日志，可使用 journalctl 或直接查看 syslog 日志文件
> 如：cat /var/log/syslog 或  cat /var/log/messages

#### crash-log-enabled
```bash
# To disable the built in crash log, which will possibly produce cleaner core
# dumps when they are needed, uncomment the following:
#
# crash-log-enabled no
```
crash-log-enabled 配置是否记录崩溃日志，默认为yes，即当Redis发生崩溃时，详细的崩溃日志将被记录在日志文件中，以帮助用户诊断和调试问题
#### crash-memcheck-enabled
```bash
# To disable the fast memory check that's run as part of the crash log, which
# will possibly let redis terminate sooner, uncomment the following:
#
# crash-memcheck-enabled no
```
crash-memcheck-enabled 配置是否启用崩溃内存检查功能，默认为yes，即在 Redis 发生崩溃时会进行内存检查，帮助诊断和调试内存相关的问题，记录内存状态和相关信息
#### databases
```bash
# Set the number of databases. The default database is DB 0, you can select
# a different one on a per-connection basis using SELECT <dbid> where
# dbid is a number between 0 and 'databases'-1
databases 16
```
databases 配置数据库数量，默认16，默认使用的数据库是DB0
#### always-show-logo
```bash
# By default Redis shows an ASCII art logo only when started to log to the
# standard output and if the standard output is a TTY and syslog logging is
# disabled. Basically this means that normally a logo is displayed only in
# interactive sessions.
#
# However it is possible to force the pre-4.0 behavior and always show a
# ASCII art logo in startup logs by setting the following option to yes.
always-show-logo no
```
always-show-logo 配置启动Redis时，是否打印logo
#### set-proc-title
#### proc-title-template
```bash
# By default, Redis modifies the process title (as seen in 'top' and 'ps') to
# provide some runtime information. It is possible to disable this and leave
# the process name as executed by setting the following to no.
set-proc-title yes

# When changing the process title, Redis uses the following template to construct
# the modified title.
#
# Template variables are specified in curly brackets. The following variables are
# supported:
#
# {title}           Name of process as executed if parent, or type of child process.
# {listen-addr}     Bind address or '*' followed by TCP or TLS port listening on, or
#                   Unix socket if only that's available.
# {server-mode}     Special mode, i.e. "[sentinel]" or "[cluster]".
# {port}            TCP port listening on, or 0.
# {tls-port}        TLS port listening on, or 0.
# {unixsocket}      Unix domain socket listening on, or "".
# {config-file}     Name of configuration file used.
#
proc-title-template "{title} {listen-addr} {server-mode}"
```
set-proc-title 和 proc-title-template 配置 Redis 进程 title 格式
> 在 top 和 ps 指令时可以显示 Redis 进程 title，默认即可

### SNAPSHOT
参考链接：[Redis官网：RDB持久化](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/)
#### save
```bash
# Save the DB to disk.
#
# save <seconds> <changes> [<seconds> <changes> ...]
#
# Redis will save the DB if the given number of seconds elapsed and it
# surpassed the given number of write operations against the DB.
#
# Snapshotting can be completely disabled with a single empty string argument
# as in following example:
#
# save ""
#
# Unless specified otherwise, by default Redis will save the DB:
#   * After 3600 seconds (an hour) if at least 1 change was performed
#   * After 300 seconds (5 minutes) if at least 100 changes were performed
#   * After 60 seconds if at least 10000 changes were performed
#
# You can set these explicitly by uncommenting the following line.
#
# save 3600 1 300 100 60 10000
```
save 配置 Redis RDB 持久化策略，默认 save 3600 1 300 100 60 10000
> - 在接下来的3600秒中，如果至少有1个key被修改，则在3600秒后保存RDB
> - 在接下来的300秒中，如果至少有10个key被修改，则在300秒后保存RDB
> - 在接下来的60秒中，如果至少有10000个key被修改，则在60秒后保存RDB

#### stop-writes-on-bgsave-error
```bash
# By default Redis will stop accepting writes if RDB snapshots are enabled
# (at least one save point) and the latest background save failed.
# This will make the user aware (in a hard way) that data is not persisting
# on disk properly, otherwise chances are that no one will notice and some
# disaster will happen.

# If the background saving process will start working again Redis will
# automatically allow writes again.

# However if you have setup your proper monitoring of the Redis server
# and persistence, you may want to disable this feature so that Redis will
# continue to work as usual even if there are problems with disk,
# permissions, and so forth.
stop-writes-on-bgsave-error yes
```
stop-writes-on-bgsave-error 配置Redis在RDB持久化出现错误时，是否停止接受写命令，默认为yes
> 这个参数的作用是在RDB持久化期间发生错误时，防止数据的丢失，确保Redis的数据完整性

#### rdbcompression
```bash
# Compress string objects using LZF when dump .rdb databases?
# By default compression is enabled as it's almost always a win.
# If you want to save some CPU in the saving child set it to 'no' but
# the dataset will likely be bigger if you have compressible values or keys.
rdbcompression yes
```
rdbcompression 配置生产RDB快照是否对数据进行压缩，默认yes
#### rdbchecksum
```bash
# Since version 5 of RDB a CRC64 checksum is placed at the end of the file.
# This makes the format more resistant to corruption but there is a performance
# hit to pay (around 10%) when saving and loading RDB files, so you can disable it
# for maximum performances.

# RDB files created with checksum disabled have a checksum of zero that will
# tell the loading code to skip the check.
rdbchecksum yes
```
rdbchecksum 配置用于控制在保存和加载 RDB 文件时是否启用校验和（checksum）功能，默认yes
> 通过校验和，Redis 能够检测到 RDB 文件中的潜在数据损坏，避免加载损坏的数据

#### sanitize-dump-payload
```bash
# Enables or disables full sanitization checks for ziplist and listpack etc when
# loading an RDB or RESTORE payload. This reduces the chances of a assertion or
# crash later on while processing commands.
# Options:
#   no         - Never perform full sanitization
#   yes        - Always perform full sanitization
#   clients    - Perform full sanitization only for user connections.
#                Excludes: RDB files, RESTORE commands received from the master
#                connection, and client connections which have the
#                skip-sanitize-payload ACL flag.
# The default should be 'clients' but since it currently affects cluster
# resharding via MIGRATE, it is temporarily set to 'no' by default.
#
# sanitize-dump-payload no
```
sanitize-dump-payload 配置项用于控制在加载 RDB 文件时是否对数据进行检查和清理，以防止潜在的恶意数据或数据损坏导致的崩溃和安全问题，默认no
#### dbfilename
```bash
# The filename where to dump the DB
dbfilename dump.rdb
```
dbfilename 配置 RDB 文件名称，默认dump.rdb
#### rdb-del-sync-files
```bash
# Remove RDB files used by replication in instances without persistence
# enabled. By default this option is disabled, however there are environments
# where for regulations or other security concerns, RDB files persisted on
# disk by masters in order to feed replicas, or stored on disk by replicas
# in order to load them for the initial synchronization, should be deleted
# ASAP. Note that this option ONLY WORKS in instances that have both AOF
# and RDB persistence disabled, otherwise is completely ignored.
#
# An alternative (and sometimes better) way to obtain the same effect is
# to use diskless replication on both master and replicas instances. However
# in the case of replicas, diskless is not always an option.
rdb-del-sync-files no
```
rdb-del-sync-files 配置 在没有启用持久化（即没有开启AOF和RDB）的Redis实例中，是否尽快删除主从复制的RDB文件，默认no
> 该配置项仅在禁用AOF和RDB持久化的实例上有效，配置为yes时，Redis在复制过程中生成的RDB文件(无论是主节点发送给从节点的RDB文件，还是从节点接收用于初始同步的RDB文件)会被尽快删除，目的是减少磁盘占用或满足某些对数据文件存留时间有严格要求的环境需求。

#### dir
```bash
# The working directory.

# The DB will be written inside this directory, with the filename specified
# above using the 'dbfilename' configuration directive.

# The Append Only File will also be created inside this directory.

# Note that you must specify a directory here, not a file name.
dir ./
```
dir 配置 RDB 文件和 AOF 文件的保存目录，默认 ./
### REPLICATION
#### replicaof
```bash
# Master-Replica replication. Use replicaof to make a Redis instance a copy of
# another Redis server. A few things to understand ASAP about Redis replication.
#
#   +------------------+      +---------------+
#   |      Master      | ---> |    Replica    |
#   | (receive writes) |      |  (exact copy) |
#   +------------------+      +---------------+
#
# 1) Redis replication is asynchronous, but you can configure a master to
#    stop accepting writes if it appears to be not connected with at least
#    a given number of replicas.
# 2) Redis replicas are able to perform a partial resynchronization with the
#    master if the replication link is lost for a relatively small amount of
#    time. You may want to configure the replication backlog size (see the next
#    sections of this file) with a sensible value depending on your needs.
# 3) Replication is automatic and does not need user intervention. After a
#    network partition replicas automatically try to reconnect to masters
#    and resynchronize with them.
#
# replicaof <masterip> <masterport>
```
replicaof 配置主从连接时，主节点的IP和端口号，无默认值
> 当前节点作为从节点时，配置主节点的IP和端口号进行连接

#### masterauth
```bash
# If the master is password protected (using the "requirepass" configuration
# directive below) it is possible to tell the replica to authenticate before
# starting the replication synchronization process, otherwise the master will
# refuse the replica request.

# masterauth <master-password>
```
masterauth 配置主从连接时，主节点要求的密码，无默认值
> 当主节点通过 requirepass 配置了密码时，当前节点作为从节点，需要通过 masterauth 来配置主节点的密码才能通过主节点权限认证

#### masteruser
```bash
# However this is not enough if you are using Redis ACLs (for Redis version
# 6 or greater), and the default user is not capable of running the PSYNC
# command and/or other commands needed for replication. In this case it's
# better to configure a special user to use with replication, and specify the
# masteruser configuration as such:

# masteruser <username>
#
# When masteruser is specified, the replica will authenticate against its
# master using the new AUTH form: AUTH <username> <password>.
```
masteruser 用于配置主从连接时，从节点作为客户端连接主节点的角色信息，默认default
#### replica-serve-stale-data
```bash
# When a replica loses its connection with the master, or when the replication
# is still in progress, the replica can act in two different ways:
#
# 1) if replica-serve-stale-data is set to 'yes' (the default) the replica will
#    still reply to client requests, possibly with out of date data, or the
#    data set may just be empty if this is the first synchronization.
#
# 2) If replica-serve-stale-data is set to 'no' the replica will reply with error
#    "MASTERDOWN Link with MASTER is down and replica-serve-stale-data is set to 'no'"
#    to all data access commands, excluding commands such as:
#    INFO, REPLICAOF, AUTH, SHUTDOWN, REPLCONF, ROLE, CONFIG, SUBSCRIBE,
#    UNSUBSCRIBE, PSUBSCRIBE, PUNSUBSCRIBE, PUBLISH, PUBSUB, COMMAND, POST,
#    HOST and LATENCY.
#
replica-serve-stale-data yes
```
replica-serve-stale-data 配置主节点与从节点失去连接或者主从复制正在进行时，从节点的行为，默认为 yes
> - yes：从节点仍响应客户端请求，但可能会有过期数据。如果这是第一次同步，则数据可能为空。
> - no：对数据访问指令返回错误（MASTERDOWN Link with MASTER is down）。但是不包括以下请求的命令：INFO, REPLICAOF, AUTH, SHUTDOWN, REPLCONF, ROLE, CONFIG, SUBSCRIBE,UNSUBSCRIBE, PSUBSCRIBE, PUNSUBSCRIBE, PUBLISH, PUBSUB, COMMAND, POST, HOST and LATENCY

#### replica-read-only
```bash
# You can configure a replica instance to accept writes or not. Writing against
# a replica instance may be useful to store some ephemeral data (because data
# written on a replica will be easily deleted after resync with the master) but
# may also cause problems if clients are writing to it because of a
# misconfiguration.
#
# Since Redis 2.6 by default replicas are read-only.
#
# Note: read only replicas are not designed to be exposed to untrusted clients
# on the internet. It's just a protection layer against misuse of the instance.
# Still a read only replica exports by default all the administrative commands
# such as CONFIG, DEBUG, and so forth. To a limited extent you can improve
# security of read only replicas using 'rename-command' to shadow all the
# administrative / dangerous commands.
replica-read-only yes
```
replica-read-only 配置从节点是否只读，默认 yes
> 集群模式中该配置项无效，集群模式可以通过readonly指令配置从节点可读，且只对当前连接有效

#### repl-diskless-sync
```bash
# Replication SYNC strategy: disk or socket.

# New replicas and reconnecting replicas that are not able to continue the
# replication process just receiving differences, need to do what is called a
# "full synchronization". An RDB file is transmitted from the master to the
# replicas.

# The transmission can happen in two different ways:

# 1) Disk-backed: The Redis master creates a new process that writes the RDB
#                 file on disk. Later the file is transferred by the parent
#                 process to the replicas incrementally.
# 2) Diskless: The Redis master creates a new process that directly writes the
#              RDB file to replica sockets, without touching the disk at all.

# With disk-backed replication, while the RDB file is generated, more replicas
# can be queued and served with the RDB file as soon as the current child
# producing the RDB file finishes its work. With diskless replication instead
# once the transfer starts, new replicas arriving will be queued and a new
# transfer will start when the current one terminates.

# When diskless replication is used, the master waits a configurable amount of
# time (in seconds) before starting the transfer in the hope that multiple
# replicas will arrive and the transfer can be parallelized.

# With slow disks and fast (large bandwidth) networks, diskless replication
# works better.
repl-diskless-sync yes
```
repl-diskless-sync 配置全量同步时，主节点是否使用 diskless（无盘）复制模式，默认 yes
> 全量同步时主节点传输RDB文件给从节点有两种方式：
> - 有盘复制：主节点 fork 一个子进程，由子进程创建RDB文件并写到磁盘，然后RDB文件由父进程传输给从节点
> - 无盘复制：主节点 fork 一个子进程，由子进程直接将 RDB 文件直接传输给从节点，不接触磁盘

#### repl-diskless-sync-delay
```bash
# When diskless replication is enabled, it is possible to configure the delay
# the server waits in order to spawn the child that transfers the RDB via socket
# to the replicas.
#
# This is important since once the transfer starts, it is not possible to serve
# new replicas arriving, that will be queued for the next RDB transfer, so the
# server waits a delay in order to let more replicas arrive.
#
# The delay is specified in seconds, and by default is 5 seconds. To disable
# it entirely just set it to 0 seconds and the transfer will start ASAP.
repl-diskless-sync-delay 5
```
repl-diskless-sync-delay 配置无盘复制时，主节点的等待时间，默认5秒
> 主节点在开始无盘复制时会等待一段时间，以期望会有多个从节点连接进来，这样主节点就可以将RDB文件传输到多个从节点。设置为0秒时，无盘复制会立即开始。

#### repl-diskless-sync-max-replicas
```bash
# When diskless replication is enabled with a delay, it is possible to let
# the replication start before the maximum delay is reached if the maximum
# number of replicas expected have connected. Default of 0 means that the
# maximum is not defined and Redis will wait the full delay.
repl-diskless-sync-max-replicas 0
```
repl-diskless-sync-max-replicas 表示在开启延时无盘复制时，在达到最大延迟时间之前就开始无盘复制
的最大从节点数量，默认为0
> 在开启延时无盘复制时，如延时5秒进行无盘复制，若在5秒内就达到无盘复制的最大从节点数量，则立即开始无盘复制，无需等待到5秒，默认为0，表示必须等待5秒

#### repl-diskless-load
```bash
# -----------------------------------------------------------------------------
# WARNING: RDB diskless load is experimental. Since in this setup the replica
# does not immediately store an RDB on disk, it may cause data loss during
# failovers. RDB diskless load + Redis modules not handling I/O reads may also
# cause Redis to abort in case of I/O errors during the initial synchronization
# stage with the master. Use only if you know what you are doing.
# -----------------------------------------------------------------------------
#
# Replica can load the RDB it reads from the replication link directly from the
# socket, or store the RDB to a file and read that file after it was completely
# received from the master.
#
# In many cases the disk is slower than the network, and storing and loading
# the RDB file may increase replication time (and even increase the master's
# Copy on Write memory and replica buffers).
# However, parsing the RDB file directly from the socket may mean that we have
# to flush the contents of the current database before the full rdb was
# received. For this reason we have the following options:
#
# "disabled"    - Don't use diskless load (store the rdb file to the disk first)
# "on-empty-db" - Use diskless load only when it is completely safe.
# "swapdb"      - Keep current db contents in RAM while parsing the data directly
#                 from the socket. Replicas in this mode can keep serving current
#                 data set while replication is in progress, except for cases where
#                 they can't recognize master as having a data set from same
#                 replication history.
#                 Note that this requires sufficient memory, if you don't have it,
#                 you risk an OOM kill.
repl-diskless-load disabled
```
repl-diskless-load 配置全量同步时从节点是否无盘加载RDB文件，默认disabled
> 警告：目前无盘加载RDB文件是是实验性的，不建议使用

#### repl-ping-replica-period
```bash
# Master send PINGs to its replicas in a predefined interval. It's possible to
# change this interval with the repl_ping_replica_period option. The default
# value is 10 seconds.
#
# repl-ping-replica-period 10
```
repl-ping-replica-period 配置主节点向从节点发送ping命令的时间间隔，默认10秒
#### repl-timeout
```bash
# The following option sets the replication timeout for:

# 1) Bulk transfer I/O during SYNC, from the point of view of replica.
# 2) Master timeout from the point of view of replicas (data, pings).
# 3) Replica timeout from the point of view of masters (REPLCONF ACK pings).

# It is important to make sure that this value is greater than the value
# specified for repl-ping-replica-period otherwise a timeout will be detected
# every time there is low traffic between the master and the replica. The default
# value is 60 seconds.
#
# repl-timeout 60
```
repl-timeout 配置主节点和从节点之间连接的超时时间，默认60秒
> 如果主节点和从节点在指定时间内未能进行通信，则认为连接已超时，并采取相应的措施，如断开连接并尝试重新连接

> 注意：repl-timeout 必须大于 repl-ping-replica-period，否则在主节点和从节点在低业务量的情况下会经常发生 timeout，导致主从断开连接

#### repl-disable-tcp-nodelay
```bash
# Disable TCP_NODELAY on the replica socket after SYNC?
#
# If you select "yes" Redis will use a smaller number of TCP packets and
# less bandwidth to send data to replicas. But this can add a delay for
# the data to appear on the replica side, up to 40 milliseconds with
# Linux kernels using a default configuration.
#
# If you select "no" the delay for data to appear on the replica side will
# be reduced but more bandwidth will be used for replication.
#
# By default we optimize for low latency, but in very high traffic conditions
# or when the master and replicas are many hops away, turning this to "yes" may
# be a good idea.
repl-disable-tcp-nodelay no
```
repl-disable-tcp-nodelay 配置是否禁用 TCP_NODELAY 选项，默认为no
> TCP_NODELAY 是一种用于优化网络延迟的 TCP 协议选项。当 TCP_NODELAY 被启用时，TCP 包会立即发送，不会进行 Nagle 算法合并，从而减少延迟；禁用该选项可能会导致稍高的延迟，但可以提高带宽利用率。

#### repl-backlog-size
```bash
# Set the replication backlog size. The backlog is a buffer that accumulates
# replica data when replicas are disconnected for some time, so that when a
# replica wants to reconnect again, often a full resync is not needed, but a
# partial resync is enough, just passing the portion of data the replica
# missed while disconnected.

# The bigger the replication backlog, the longer the replica can endure the
# disconnect and later be able to perform a partial resynchronization.

# The backlog is only allocated if there is at least one replica connected.
#
# repl-backlog-size 1mb
```
repl-backlog-size 配置复制积压缓冲区大小，默认1MB
> 复制积压缓冲区是一个在主节点上的先进先出的定长队列，主节点不仅会把写命令发送给从节点，还会写入复制积压缓冲区。当从节点断开连接时间较短，并重新连接时，通过复制积压缓冲区可进行部分同步，而不是全量同步

#### repl-backlog-ttl
```bash
# After a master has no connected replicas for some time, the backlog will be
# freed. The following option configures the amount of seconds that need to
# elapse, starting from the time the last replica disconnected, for the backlog
# buffer to be freed.

# Note that replicas never free the backlog for timeout, since they may be
# promoted to masters later, and should be able to correctly "partially
# resynchronize" with other replicas: hence they should always accumulate backlog.

# A value of 0 means to never release the backlog.
#
# repl-backlog-ttl 3600
```
repl-backlog-ttl 配置复制积压缓冲区保留时间，默认3600秒
> 当所有从节点断开连接后，主节点会等待一段时间后释放复制积压缓冲区，默认3600秒，0表示永不释放

#### replica-priority
```bash
# The replica priority is an integer number published by Redis in the INFO
# output. It is used by Redis Sentinel in order to select a replica to promote
# into a master if the master is no longer working correctly.

# A replica with a low priority number is considered better for promotion, so
# for instance if there are three replicas with priority 10, 100, 25 Sentinel
# will pick the one with priority 10, that is the lowest.

# However a special priority of 0 marks the replica as not able to perform the
# role of master, so a replica with priority of 0 will never be selected by
# Redis Sentinel for promotion.

# By default the priority is 100.
replica-priority 100
```
replica-priority 配置从节点的优先级，默认100
> 主要影响哨兵节点在主节点宕机时选择新的主节点，当多个从节点有资格成为新的主节点时，哨兵节点会优先选择优先级较高的从节点，数值越小，优先级越高

#### propagation-error-behavior 
```bash
# The propagation error behavior controls how Redis will behave when it is
# unable to handle a command being processed in the replication stream from a master
# or processed while reading from an AOF file. Errors that occur during propagation
# are unexpected, and can cause data inconsistency. However, there are edge cases
# in earlier versions of Redis where it was possible for the server to replicate or persist
# commands that would fail on future versions. For this reason the default behavior
# is to ignore such errors and continue processing commands.

# If an application wants to ensure there is no data divergence, this configuration
# should be set to 'panic' instead. The value can also be set to 'panic-on-replicas'
# to only panic when a replica encounters an error on the replication stream. One of
# these two panic values will become the default value in the future once there are
# sufficient safety mechanisms in place to prevent false positive crashes.

# propagation-error-behavior ignore
```
propagation-error-behavior 配置在传播命令过程中发生错误时的行为，默认ignore
> 指令传播过程中可能会发生意外错误，导致数据不一致：
> ignore: 忽略错误并继续处理命令
> panic: 当主节点或从节点在主从复制或 AOF 文件中的命令时遇到错误，立即触发panic并停止处理
> panic-on-replicas: 仅从节点在主从复制时遇到错误时触发panic

#### replica-ignore-disk-write-errors
```bash
# Replica ignore disk write errors controls the behavior of a replica when it is
# unable to persist a write command received from its master to disk. By default,
# this configuration is set to 'no' and will crash the replica in this condition.
# It is not recommended to change this default, however in order to be compatible
# with older versions of Redis this config can be toggled to 'yes' which will just
# log a warning and execute the write command it got from the master.
#
# replica-ignore-disk-write-errors no
```
replica-ignore-disk-write-errors 配置从节点无法将接收到的写命令持久化到磁盘时是否忽略错误并执行这个写命令，默认no
#### replica-announced
```bash
# By default, Redis Sentinel includes all replicas in its reports. A replica
# can be excluded from Redis Sentinel's announcements. An unannounced replica
# will be ignored by the 'sentinel replicas <master>' command and won't be
# exposed to Redis Sentinel's clients.

# This option does not change the behavior of replica-priority. Even with
# replica-announced set to 'no', the replica can be promoted to master. To
# prevent this behavior, set replica-priority to 0.

# replica-announced yes
```
replica-announced 配置从节点是否在 INFO replication 输出中向客户端报告自己，默认yes
#### min-replicas-to-write 
#### min-replicas-max-lag
```bash
# It is possible for a master to stop accepting writes if there are less than
# N replicas connected, having a lag less or equal than M seconds.

# The N replicas need to be in "online" state.

# The lag in seconds, that must be <= the specified value, is calculated from
# the last ping received from the replica, that is usually sent every second.

# This option does not GUARANTEE that N replicas will accept the write, but
# will limit the window of exposure for lost writes in case not enough replicas
# are available, to the specified number of seconds.

# For example to require at least 3 replicas with a lag <= 10 seconds use:
#
# min-replicas-to-write 3
# min-replicas-max-lag 10
# 
# Setting one or the other to 0 disables the feature.

# By default min-replicas-to-write is set to 0 (feature disabled) and
# min-replicas-max-lag is set to 10.
```
min-replicas-to-write 和 min-replicas-max-lag 配置跟主节点连接的从节点延时小于M 秒的个数小于N 个，主节点将停止接收写命令
> min-replicas-to-write 默认3，min-replicas-max-lag 默认10，即跟主节点连接的从节点延时小于10秒的从节点个数小于3个，则主节点停止接收写命令

#### replica-announce-ip
#### replica-announce-port
```bash
# A Redis master is able to list the address and port of the attached
# replicas in different ways. For example the "INFO replication" section
# offers this information, which is used, among other tools, by
# Redis Sentinel in order to discover replica instances.
# Another place where this info is available is in the output of the
# "ROLE" command of a master.
#
# The listed IP address and port normally reported by a replica is
# obtained in the following way:

#   IP: The address is auto detected by checking the peer address
#   of the socket used by the replica to connect with the master.

#   Port: The port is communicated by the replica during the replication
#   handshake, and is normally the port that the replica is using to
#   listen for connections.
#
# However when port forwarding or Network Address Translation (NAT) is
# used, the replica may actually be reachable via different IP and port
# pairs. The following two options can be used by a replica in order to
# report to its master a specific set of IP and port, so that both INFO
# and ROLE will report those values.
#
# There is no need to use both the options if you need to override just
# the port or the IP address.
#
# replica-announce-ip 5.5.5.5
# replica-announce-port 1234
```
replica-announce-ip 和 replica-announce-port 允许从节点在与主节点通信时报告的IP和端口号
> 当从节点处于 NAT 地址转换或者使用端口转发时，自动检测的IP和端口号可能不准确，此配置项可以覆盖自动检测的IP和端口号，主节点可以通过 INFO replication 或 ROLE 指令来查看从节点信息

### keys tracking
#### tracking-table-max-keys
```bash
# Redis implements server assisted support for client side caching of values.
# This is implemented using an invalidation table that remembers, using
# a radix key indexed by key name, what clients have which keys. In turn
# this is used in order to send invalidation messages to clients. Please
# check this page to understand more about the feature:

#   https://redis.io/topics/client-side-caching

# When tracking is enabled for a client, all the read only queries are assumed
# to be cached: this will force Redis to store information in the invalidation
# table. When keys are modified, such information is flushed away, and
# invalidation messages are sent to the clients. However if the workload is
# heavily dominated by reads, Redis could use more and more memory in order
# to track the keys fetched by many clients.

# For this reason it is possible to configure a maximum fill value for the
# invalidation table. By default it is set to 1M of keys, and once this limit
# is reached, Redis will start to evict keys in the invalidation table
# even if they were not modified, just to reclaim memory: this will in turn
# force the clients to invalidate the cached values. Basically the table
# maximum size is a trade off between the memory you want to spend server
# side to track information about who cached what, and the ability of clients
# to retain cached objects in memory.

# If you set the value to 0, it means there are no limits, and Redis will
# retain as many keys as needed in the invalidation table.
# In the "stats" INFO section, you can find information about the number of
# keys in the invalidation table at every given moment.

# Note: when key tracking is used in broadcasting mode, no memory is used
# in the server side so this setting is useless.
#
# tracking-table-max-keys 1000000
```
tracking-table-max-keys 配置客户端缓存无效表的最大键数，默认1000000
> 当 Redis 进行客户端缓存时，会跟踪哪些客户端缓存了哪些键，以便在键被修改时向客户端发送无效消息。如果无效表的键数超过了这个配置项设定的最大值，Redis 将开始驱逐未被修改的键以回收内存，这有助于控制 Redis 为跟踪缓存信息所使用的内存量
> 参考链接：
> [https://redis.io/docs/manual/client-side-caching/](https://redis.io/docs/manual/client-side-caching/)

> 客户端缓存模式：
> - 默认模式，Redis 记住哪些客户端访问了哪些key，并在修改 key 时向客户端发送无效消息，这样会消耗服务端内存。上述无效表属于默认模式
> - 广播模式，Redis不会记住客户端访问了哪些key，客户端会订阅 object: 或 user: 这样的key前缀，当带有订阅前缀的 key 被修改时，服务端会把失效消息广播给所有订阅的客户端

### security
```bash
# Warning: since Redis is pretty fast, an outside user can try up to
# 1 million passwords per second against a modern box. This means that you
# should use very strong passwords, otherwise they will be very easy to break.
# Note that because the password is really a shared secret between the client
# and the server, and should not be memorized by any human, the password
# can be easily a long string from /dev/urandom or whatever, so by using a
# long and unguessable password no brute force attack will be possible.

# Redis ACL users are defined in the following format:
#
#   user <username> ... acl rules ...
#
# For example:
#
#   user worker +@list +@connection ~jobs:* on >ffa9203c493aa99
#
# The special username "default" is used for new connections. If this user
# has the "nopass" rule, then new connections will be immediately authenticated
# as the "default" user without the need of any password provided via the
# AUTH command. Otherwise if the "default" user is not flagged with "nopass"
# the connections will start in not authenticated state, and will require
# AUTH (or the HELLO command AUTH option) in order to be authenticated and
# start to work.
#
# The ACL rules that describe what a user can do are the following:
#
#  on           Enable the user: it is possible to authenticate as this user.
#  off          Disable the user: it's no longer possible to authenticate
#               with this user, however the already authenticated connections
#               will still work.
#  skip-sanitize-payload    RESTORE dump-payload sanitization is skipped.
#  sanitize-payload         RESTORE dump-payload is sanitized (default).
#  +<command>   Allow the execution of that command.
#               May be used with `|` for allowing subcommands (e.g "+config|get")
#  -<command>   Disallow the execution of that command.
#               May be used with `|` for blocking subcommands (e.g "-config|set")
#  +@<category> Allow the execution of all the commands in such category
#               with valid categories are like @admin, @set, @sortedset, ...
#               and so forth, see the full list in the server.c file where
#               the Redis command table is described and defined.
#               The special category @all means all the commands, but currently
#               present in the server, and that will be loaded in the future
#               via modules.
#  +<command>|first-arg  Allow a specific first argument of an otherwise
#                        disabled command. It is only supported on commands with
#                        no sub-commands, and is not allowed as negative form
#                        like -SELECT|1, only additive starting with "+". This
#                        feature is deprecated and may be removed in the future.
#  allcommands  Alias for +@all. Note that it implies the ability to execute
#               all the future commands loaded via the modules system.
#  nocommands   Alias for -@all.
#  ~<pattern>   Add a pattern of keys that can be mentioned as part of
#               commands. For instance ~* allows all the keys. The pattern
#               is a glob-style pattern like the one of KEYS.
#               It is possible to specify multiple patterns.
# %R~<pattern>  Add key read pattern that specifies which keys can be read 
#               from.
# %W~<pattern>  Add key write pattern that specifies which keys can be
#               written to. 
#  allkeys      Alias for ~*
#  resetkeys    Flush the list of allowed keys patterns.
#  &<pattern>   Add a glob-style pattern of Pub/Sub channels that can be
#               accessed by the user. It is possible to specify multiple channel
#               patterns.
#  allchannels  Alias for &*
#  resetchannels            Flush the list of allowed channel patterns.
#  ><password>  Add this password to the list of valid password for the user.
#               For example >mypass will add "mypass" to the list.
#               This directive clears the "nopass" flag (see later).
#  <<password>  Remove this password from the list of valid passwords.
#  nopass       All the set passwords of the user are removed, and the user
#               is flagged as requiring no password: it means that every
#               password will work against this user. If this directive is
#               used for the default user, every new connection will be
#               immediately authenticated with the default user without
#               any explicit AUTH command required. Note that the "resetpass"
#               directive will clear this condition.
#  resetpass    Flush the list of allowed passwords. Moreover removes the
#               "nopass" status. After "resetpass" the user has no associated
#               passwords and there is no way to authenticate without adding
#               some password (or setting it as "nopass" later).
#  reset        Performs the following actions: resetpass, resetkeys, off,
#               -@all. The user returns to the same state it has immediately
#               after its creation.
# (<options>)   Create a new selector with the options specified within the
#               parentheses and attach it to the user. Each option should be 
#               space separated. The first character must be ( and the last 
#               character must be ).
# clearselectors            Remove all of the currently attached selectors. 
#                           Note this does not change the "root" user permissions,
#                           which are the permissions directly applied onto the
#                           user (outside the parentheses).
#
# ACL rules can be specified in any order: for instance you can start with
# passwords, then flags, or key patterns. However note that the additive
# and subtractive rules will CHANGE MEANING depending on the ordering.
# For instance see the following example:
#
#   user alice on +@all -DEBUG ~* >somepassword
#
# This will allow "alice" to use all the commands with the exception of the
# DEBUG command, since +@all added all the commands to the set of the commands
# alice can use, and later DEBUG was removed. However if we invert the order
# of two ACL rules the result will be different:
#
#   user alice on -DEBUG +@all ~* >somepassword
#
# Now DEBUG was removed when alice had yet no commands in the set of allowed
# commands, later all the commands are added, so the user will be able to
# execute everything.
#
# Basically ACL rules are processed left-to-right.
#
# The following is a list of command categories and their meanings:
# * keyspace - Writing or reading from keys, databases, or their metadata 
#     in a type agnostic way. Includes DEL, RESTORE, DUMP, RENAME, EXISTS, DBSIZE,
#     KEYS, EXPIRE, TTL, FLUSHALL, etc. Commands that may modify the keyspace,
#     key or metadata will also have `write` category. Commands that only read
#     the keyspace, key or metadata will have the `read` category.
# * read - Reading from keys (values or metadata). Note that commands that don't
#     interact with keys, will not have either `read` or `write`.
# * write - Writing to keys (values or metadata)
# * admin - Administrative commands. Normal applications will never need to use
#     these. Includes REPLICAOF, CONFIG, DEBUG, SAVE, MONITOR, ACL, SHUTDOWN, etc.
# * dangerous - Potentially dangerous (each should be considered with care for
#     various reasons). This includes FLUSHALL, MIGRATE, RESTORE, SORT, KEYS,
#     CLIENT, DEBUG, INFO, CONFIG, SAVE, REPLICAOF, etc.
# * connection - Commands affecting the connection or other connections.
#     This includes AUTH, SELECT, COMMAND, CLIENT, ECHO, PING, etc.
# * blocking - Potentially blocking the connection until released by another
#     command.
# * fast - Fast O(1) commands. May loop on the number of arguments, but not the
#     number of elements in the key.
# * slow - All commands that are not Fast.
# * pubsub - PUBLISH / SUBSCRIBE related
# * transaction - WATCH / MULTI / EXEC related commands.
# * scripting - Scripting related.
# * set - Data type: sets related.
# * sortedset - Data type: zsets related.
# * list - Data type: lists related.
# * hash - Data type: hashes related.
# * string - Data type: strings related.
# * bitmap - Data type: bitmaps related.
# * hyperloglog - Data type: hyperloglog related.
# * geo - Data type: geo related.
# * stream - Data type: streams related.
#
# For more information about ACL configuration please refer to
# the Redis web site at https://redis.io/topics/acl
```
ACL具体用法，内容较多，参考链接如下：

- [https://redis.io/docs/management/security/acl/](https://redis.io/docs/management/security/acl/)
- [https://www.cnblogs.com/weihanli/p/redis-acl-intro.html](https://www.cnblogs.com/weihanli/p/redis-acl-intro.html)
#### acllog-max-len
```bash
# ACL LOG

# The ACL Log tracks failed commands and authentication events associated
# with ACLs. The ACL Log is useful to troubleshoot failed commands blocked
# by ACLs. The ACL Log is stored in memory. You can reclaim memory with
# ACL LOG RESET. Define the maximum entry length of the ACL Log below.
acllog-max-len 128
```
acllog-max-len 配置 ACL日志的最大长度，默认128
> ACL日志跟踪与ACL关联的失败命令和身份验证事件，保并存在内存中，使用 ACL LOG 指令查看，可以使用ACL LOG RESET来回收内存

#### aclfile
```bash
# Using an external ACL file
#
# Instead of configuring users here in this file, it is possible to use
# a stand-alone file just listing users. The two methods cannot be mixed:
# if you configure users here and at the same time you activate the external
# ACL file, the server will refuse to start.
#
# The format of the external ACL user file is exactly the same as the
# format that is used inside redis.conf to describe users.
#
# aclfile /etc/redis/users.acl
```
aclfile 指定 ACL 文件，无默认值
> 配置ACL有如下两种方式：
> - 在 redis.conf 中直接配置，CONFIG REWRITE 指令可将新的用户配置存储在 redis.conf 文件中
> - 使用 ACL 外部文件，功能更强大，如 ACL LOAD 指令可重新加载外部 ACL 文件，ACL SAVE 命令可将当前 ACL 配置保存到外部文件中
> 
只能选择一种方式使用 ACL，前者简单易用，但在有较多个用户要定义的复杂环境中，建议使用ACL文件

#### requirepass
```bash
# IMPORTANT NOTE: starting with Redis 6 "requirepass" is just a compatibility
# layer on top of the new ACL system. The option effect will be just setting
# the password for the default user. Clients will still authenticate using
# AUTH <password> as usually, or more explicitly with AUTH default <password>
# if they follow the new protocol: both will work.

# The requirepass is not compatible with aclfile option and the ACL LOAD
# command, these will cause requirepass to be ignored.
#
# requirepass foobared
```
requirepass 配置密码，无默认值
> 从 Redis6 开始，requirepass 目前只是为 default 用户设置密码

#### acl-pubsub-default
```bash
# New users are initialized with restrictive permissions by default, via the
# equivalent of this ACL rule 'off resetkeys -@all'. Starting with Redis 6.2, it
# is possible to manage access to Pub/Sub channels with ACL rules as well. The
# default Pub/Sub channels permission if new users is controlled by the
# acl-pubsub-default configuration directive, which accepts one of these values:

# allchannels: grants access to all Pub/Sub channels
# resetchannels: revokes access to all Pub/Sub channels

# From Redis 7.0, acl-pubsub-default defaults to 'resetchannels' permission.

# acl-pubsub-default resetchannels
```
acl-pubsub-default 配置 ACL 新增用户的发布订阅权限
> 从 Redis 6.2 开始，ACL 还提供 Pub/Sub 权限管理，默认新用户被授予 allchannels 权限
> 从 Redis 7.0 开始，默认新用户被授予为 resetchannels

#### rename-command
```bash
# Command renaming (DEPRECATED).
#
# ------------------------------------------------------------------------
# WARNING: avoid using this option if possible. Instead use ACLs to remove
# commands from the default user, and put them only in some admin user you
# create for administrative purposes.
# ------------------------------------------------------------------------
#
# It is possible to change the name of dangerous commands in a shared
# environment. For instance the CONFIG command may be renamed into something
# hard to guess so that it will still be available for internal-use tools
# but not available for general clients.
#
# Example:
#
# rename-command CONFIG b840fc02d524045429941cc15f59e41cb7be6c52
#
# It is also possible to completely kill a command by renaming it into
# an empty string:
#
# rename-command CONFIG ""
#
# Please note that changing the name of commands that are logged into the
# AOF file or transmitted to replicas may cause problems.
```
rename-command 用于命令重命名
> 警告：该配置比较危险，已经废弃，不建议使用，如果需要对用户进行限制，可以使用ACL指令代替

### CLIENTS
#### maxclients
```bash
# Set the max number of connected clients at the same time. By default
# this limit is set to 10000 clients, however if the Redis server is not
# able to configure the process file limit to allow for the specified limit
# the max number of allowed clients is set to the current file limit
# minus 32 (as Redis reserves a few file descriptors for internal uses).

# Once the limit is reached Redis will close all the new connections sending
# an error 'max number of clients reached'.

# IMPORTANT: When Redis Cluster is used, the max number of connections is also
# shared with the cluster bus: every node in the cluster will use two
# connections, one incoming and another outgoing. It is important to size the
# limit accordingly in case of very large clusters.
#
# maxclients 10000
```
maxclients 配置最大客户端连接数，默认10000
> 当 Redis 达到最大客户端连接数时，会关闭新的客户端连接并报错

### MEMORY MANAGEMENT
#### maxmemory
```bash
# Set a memory usage limit to the specified amount of bytes.
# When the memory limit is reached Redis will try to remove keys
# according to the eviction policy selected (see maxmemory-policy).

# If Redis can't remove keys according to the policy, or if the policy is
# set to 'noeviction', Redis will start to reply with errors to commands
# that would use more memory, like SET, LPUSH, and so on, and will continue
# to reply to read-only commands like GET.

# This option is usually useful when using Redis as an LRU or LFU cache, or to
# set a hard memory limit for an instance (using the 'noeviction' policy).

# WARNING: If you have replicas attached to an instance with maxmemory on,
# the size of the output buffers needed to feed the replicas are subtracted
# from the used memory count, so that network problems / resyncs will
# not trigger a loop where keys are evicted, and in turn the output
# buffer of replicas is full with DELs of keys evicted triggering the deletion
# of more keys, and so forth until the database is completely emptied.

# In short... if you have replicas attached it is suggested that you set a lower
# limit for maxmemory so that there is some free RAM on the system for replica
# output buffers (but this is not needed if the policy is 'noeviction').
#
# maxmemory <bytes>
```
maxmemory 配置 Redis 的最大内存，无默认值
> 当内存达到限制时，Redis 将尝试根据驱逐策略释放内存，如果Redis不能根据策略删除键，或者策略是noeviction，Redis 将报错，并只响应GET等只读命令

#### maxmemory-policy
```bash
# MAXMEMORY POLICY: how Redis will select what to remove when maxmemory
# is reached. You can select one from the following behaviors:

# volatile-lru -> Evict using approximated LRU, only keys with an expire set.
# allkeys-lru -> Evict any key using approximated LRU.
# volatile-lfu -> Evict using approximated LFU, only keys with an expire set.
# allkeys-lfu -> Evict any key using approximated LFU.
# volatile-random -> Remove a random key having an expire set.
# allkeys-random -> Remove a random key, any key.
# volatile-ttl -> Remove the key with the nearest expire time (minor TTL)
# noeviction -> Don't evict anything, just return an error on write operations.

# LRU means Least Recently Used
# LFU means Least Frequently Used

# Both LRU, LFU and volatile-ttl are implemented using approximated
# randomized algorithms.

# Note: with any of the above policies, when there are no suitable keys for
# eviction, Redis will return an error on write operations that require
# more memory. These are usually commands that create new keys, add data or
# modify existing keys. A few examples are: SET, INCR, HSET, LPUSH, SUNIONSTORE,
# SORT (due to the STORE argument), and EXEC (if the transaction includes any
# command that requires memory).

# The default is:

# maxmemory-policy noeviction
```
maxmemory-policy 配置达到最大内存时的驱逐策略，默认 noeviction
> - volatile-lru：在有设置过期时间的key中，使用LRU算法淘汰最近最少使用的key
> - allkeys-lru：在所有的key中，使用LRU算法淘汰最近最少使用的key
> - volatile-lfu：在有设置过期时间的key中，使用LFU算法淘汰最不经常使用的key
> - allkeys-lfu：在所有的key中，使用LFU算法淘汰最不经常使用的键key
> - volatile-random：在有设置过期时间的key中，随机选择key进行淘汰
> - allkeys-random：在所有的key中，随机选择key进行淘汰
> - volatile-ttl：在有设置过期时间的key中，选择最早过期的key进行淘汰
> - noeviction：不淘汰key，并返回错误
> 
注意：不论使用何种策略，当没有合适的key用于驱逐时，由于内存不足，Redis 在执行写指令时将报错

#### maxmemory-samples
```bash
# LRU, LFU and minimal TTL algorithms are not precise algorithms but approximated
# algorithms (in order to save memory), so you can tune it for speed or
# accuracy. By default Redis will check five keys and pick the one that was
# used least recently, you can change the sample size using the following
# configuration directive.
#
# The default of 5 produces good enough results. 10 Approximates very closely
# true LRU but costs more CPU. 3 is faster but not very accurate.
#
# maxmemory-samples 5
```
maxmemory-samples 配置 Redis 驱逐key时采样的key的数量，默认5
> Redis 使用近似算法来选择要驱逐的key，通过一定数量的采样来决定哪个key应该被驱逐，采样数量越多越精确，但也会增加 CPU 开销

#### maxmemory-eviction-tenacity
```bash
# Eviction processing is designed to function well with the default setting.
# If there is an unusually large amount of write traffic, this value may need to
# be increased.  Decreasing this value may reduce latency at the risk of
# eviction processing effectiveness
#   0 = minimum latency, 10 = default, 100 = process without regard to latency

# maxmemory-eviction-tenacity 10
```
maxmemory-eviction-tenacity 配置 Redis 在尝试驱逐key时的坚持程度，默认10
> 该值越高，Redis 在达到 maxmemory 限制时会更积极地尝试驱逐键，以释放内存

> 参考链接：[https://redis.io/docs/reference/eviction/](https://redis.io/docs/reference/eviction/)

#### replica-ignore-maxmemory
```bash
# Starting from Redis 5, by default a replica will ignore its maxmemory setting
# (unless it is promoted to master after a failover or manually). It means
# that the eviction of keys will be just handled by the master, sending the
# DEL commands to the replica as keys evict in the master side.
#
# This behavior ensures that masters and replicas stay consistent, and is usually
# what you want, however if your replica is writable, or you want the replica
# to have a different memory setting, and you are sure all the writes performed
# to the replica are idempotent, then you may change this default (but be sure
# to understand what you are doing).
#
# Note that since the replica by default does not evict, it may end using more
# memory than the one set via maxmemory (there are certain buffers that may
# be larger on the replica, or data structures may sometimes take more memory
# and so forth). So make sure you monitor your replicas and make sure they
# have enough memory to never hit a real out-of-memory condition before the
# master hits the configured maxmemory setting.
#
# replica-ignore-maxmemory yes
```
replica-ignore-maxmemory 配置从节点是否忽略 maxmemory 限制，默认yes
> 从Redis5 开始，从节点默认忽略 maxmemory 限制，此时如果主节点驱逐了一个key，将发送 del 命令到从节点删除这个key

#### active-expire-effort
```bash
# Redis reclaims expired keys in two ways: upon access when those keys are
# found to be expired, and also in background, in what is called the
# "active expire key". The key space is slowly and interactively scanned
# looking for expired keys to reclaim, so that it is possible to free memory
# of keys that are expired and will never be accessed again in a short time.

# The default effort of the expire cycle will try to avoid having more than
# ten percent of expired keys still in memory, and will try to avoid consuming
# more than 25% of total memory and to add latency to the system. However
# it is possible to increase the expire "effort" that is normally set to
# "1", to a greater value, up to the value "10". At its maximum value the
# system will use more CPU, longer cycles (and technically may introduce
# more latency), and will tolerate less already expired keys still present
# in the system. It's a tradeoff between memory, CPU and latency.
#
# active-expire-effort 1
```
active-expire-effort 配置 Redis 主动删除过期键的努力程度，默认1
> Redis 定期扫描一部分键空间来删除过期键，active-expire-effort 决定了扫描的频率和力度，通常在1-10 之间，值越大意味着系统会使用更的的cpu资源

### LAZY FREEING
#### lazyfree-lazy-eviction
#### lazyfree-lazy-expire
#### lazyfree-lazy-server-del
#### replica-lazy-flush
```bash
# Redis has two primitives to delete keys. One is called DEL and is a blocking
# deletion of the object. It means that the server stops processing new commands
# in order to reclaim all the memory associated with an object in a synchronous
# way. If the key deleted is associated with a small object, the time needed
# in order to execute the DEL command is very small and comparable to most other
# O(1) or O(log_N) commands in Redis. However if the key is associated with an
# aggregated value containing millions of elements, the server can block for
# a long time (even seconds) in order to complete the operation.

# For the above reasons Redis also offers non blocking deletion primitives
# such as UNLINK (non blocking DEL) and the ASYNC option of FLUSHALL and
# FLUSHDB commands, in order to reclaim memory in background. Those commands
# are executed in constant time. Another thread will incrementally free the
# object in the background as fast as possible.

# DEL, UNLINK and ASYNC option of FLUSHALL and FLUSHDB are user-controlled.
# It's up to the design of the application to understand when it is a good
# idea to use one or the other. However the Redis server sometimes has to
# delete keys or flush the whole database as a side effect of other operations.
# Specifically Redis deletes objects independently of a user call in the
# following scenarios:

# 1) On eviction, because of the maxmemory and maxmemory policy configurations,
#    in order to make room for new data, without going over the specified
#    memory limit.
# 2) Because of expire: when a key with an associated time to live (see the
#    EXPIRE command) must be deleted from memory.
# 3) Because of a side effect of a command that stores data on a key that may
#    already exist. For example the RENAME command may delete the old key
#    content when it is replaced with another one. Similarly SUNIONSTORE
#    or SORT with STORE option may delete existing keys. The SET command
#    itself removes any old content of the specified key in order to replace
#    it with the specified string.
# 4) During replication, when a replica performs a full resynchronization with
#    its master, the content of the whole database is removed in order to
#    load the RDB file just transferred.
#
# In all the above cases the default is to delete objects in a blocking way,
# like if DEL was called. However you can configure each case specifically
# in order to instead release memory in a non-blocking way like if UNLINK
# was called, using the following configuration directives.

lazyfree-lazy-eviction no
lazyfree-lazy-expire no
lazyfree-lazy-server-del no
replica-lazy-flush no
```

- lazyfree-lazy-eviction 配置是否在驱逐key时使用惰性删除，默认no。当启用该选项时，驱逐操作将由后台线程负责，而不是在主线程中立即完成
- lazyfree-lazy-expire 配置是否在key过期时使用惰性删除，默认no。当启用该选项时，过期key的删除操作将由后台线程处理，而不是在主线程中立即完成
- lazyfree-lazy-server-del 配置在命令副作用导致删除时是否使用惰性删除，默认no。当启用该选项时，删除操作将由后台线程处理，而不是在主线程中立即完，如SET命令会删除key的旧内容，并新内容替换，如果是一个big key，则可能会阻塞
- replica-lazy-flush 配置从节点在进行全量同步操作时是否使用惰性删除，默认no。当启用该选项时，从节点在接收到全量同步命令时，将异步删除现有数据，而不是在主线程中立即完成
#### lazyfree-lazy-user-del
```bash
# It is also possible, for the case when to replace the user code DEL calls
# with UNLINK calls is not easy, to modify the default behavior of the DEL
# command to act exactly like UNLINK, using the following configuration
# directive:

lazyfree-lazy-user-del no
```
lazyfree-lazy-user-del 配置 DEL 命令的删除操作是否使用惰性删除，默认no
#### lazyfree-lazy-user-flush
```bash
# FLUSHDB, FLUSHALL, SCRIPT FLUSH and FUNCTION FLUSH support both asynchronous and synchronous
# deletion, which can be controlled by passing the [SYNC|ASYNC] flags into the
# commands. When neither flag is passed, this directive will be used to determine
# if the data should be deleted asynchronously.

lazyfree-lazy-user-flush no
```
lazyfree-lazy-user-del 配置 FLUSHDB、FLUSHALL、SCRIPT FLUSH 和 FUNCTION FLUSH 命令是否使用惰性删除，默认no
### THREADED I/O
#### io-threads
```bash
# Redis is mostly single threaded, however there are certain threaded
# operations such as UNLINK, slow I/O accesses and other things that are
# performed on side threads.
#
# Now it is also possible to handle Redis clients socket reads and writes
# in different I/O threads. Since especially writing is so slow, normally
# Redis users use pipelining in order to speed up the Redis performances per
# core, and spawn multiple instances in order to scale more. Using I/O
# threads it is possible to easily speedup two times Redis without resorting
# to pipelining nor sharding of the instance.
#
# By default threading is disabled, we suggest enabling it only in machines
# that have at least 4 or more cores, leaving at least one spare core.
# Using more than 8 threads is unlikely to help much. We also recommend using
# threaded I/O only if you actually have performance problems, with Redis
# instances being able to use a quite big percentage of CPU time, otherwise
# there is no point in using this feature.
#
# So for instance if you have a four cores boxes, try to use 2 or 3 I/O
# threads, if you have a 8 cores, try to use 6 threads. In order to
# enable I/O threads use the following configuration directive:
#
# io-threads 4
```
io-threads 指定用于处理 I/O 操作的线程数量，默认 Redis 仅使用主线程处理所有操作（包括 I/O），启用 I/O 线程可以将网络 I/O 从主线程中分离出来，以提高性能
> 建议仅在实际遇到性能问题时才使用多线程 I/O，并至少留一个核心作为备用。

#### io-threads-do-reads
```bash
# Setting io-threads to 1 will just use the main thread as usual.
# When I/O threads are enabled, we only use threads for writes, that is
# to thread the write(2) syscall and transfer the client buffers to the
# socket. However it is also possible to enable threading of reads and
# protocol parsing using the following configuration directive, by setting
# it to yes:
#
# io-threads-do-reads no
#
# Usually threading reads doesn't help much.
#
# NOTE 1: This configuration directive cannot be changed at runtime via
# CONFIG SET. Also, this feature currently does not work when SSL is
# enabled.
#
# NOTE 2: If you want to test the Redis speedup using redis-benchmark, make
# sure you also run the benchmark itself in threaded mode, using the
# --threads option to match the number of Redis threads, otherwise you'll not
# be able to notice the improvements.
```
io-threads-do-reads 配置 I/O 线程是否负责读取操作，默认 no
> 如果设置为 yes，I/O 线程不仅负责写操作，还负责读操作；如果设置为 no，读操作仍由主线程处理

### KERNEL OOM CONTROL
#### oom-score-adj
```bash
# On Linux, it is possible to hint the kernel OOM killer on what processes
# should be killed first when out of memory.
#
# Enabling this feature makes Redis actively control the oom_score_adj value
# for all its processes, depending on their role. The default scores will
# attempt to have background child processes killed before all others, and
# replicas killed before masters.
#
# Redis supports these options:
#
# no:       Don't make changes to oom-score-adj (default).
# yes:      Alias to "relative" see below.
# absolute: Values in oom-score-adj-values are written as is to the kernel.
# relative: Values are used relative to the initial value of oom_score_adj when
#           the server starts and are then clamped to a range of -1000 to 1000.
#           Because typically the initial value is 0, they will often match the
#           absolute values.
oom-score-adj no
```
oom-score-adj 配置是否启用 oom_score_adj 设置，默认 no
> oom_score_adj 是 Linux 内核中的一个参数，用于调整进程的 OOM 优先级。当系统内存不足时，内核会选择 OOM 优先级较高的进程进行杀死，以释放内存

#### oom-score-adj-values
```bash
# When oom-score-adj is used, this directive controls the specific values used
# for master, replica and background child processes. Values range -2000 to
# 2000 (higher means more likely to be killed).

# Unprivileged processes (not root, and without CAP_SYS_RESOURCE capabilities)
# can freely increase their value, but not decrease it below its initial
# settings. This means that setting oom-score-adj to "relative" and setting the
# oom-score-adj-values to positive values will always succeed.
oom-score-adj-values 0 200 800
```
oom-score-adj-values 指定 Redis 不同进程的 oom_score_adj 值，默认 0 200 800，表示主节点是0，从节点200，子进程800，即被 kill 的优先级：子进程 > 从节点 > 主节点
> 当 oom-score-adj 设置为 yes 时，Redis 将根据 oom-score-adj-values 配置的值来调整 Linux 系统的oom_score_adj 参数，值越高优先级越高，越容易被 kill

### KERNEL transparent hugepage CONTROL
#### disable-thp
```bash
# Usually the kernel Transparent Huge Pages control is set to "madvise" or
# or "never" by default (/sys/kernel/mm/transparent_hugepage/enabled), in which
# case this config has no effect. On systems in which it is set to "always",
# redis will attempt to disable it specifically for the redis process in order
# to avoid latency problems specifically with fork(2) and CoW.
# If for some reason you prefer to keep it enabled, you can set this config to
# "no" and the kernel global to "always".

disable-thp yes
```
disable-thp 配置是否禁用透明大页（Transparent Huge Pages，THP），默认yes
> THP 是一种内存管理特性，旨在提高内存的使用效率和性能，但在这种特性可能会对 Redis 等内存密集型应用产生负面影响

### APPEND ONLY MODE
#### appendonly
```bash
# By default Redis asynchronously dumps the dataset on disk. This mode is
# good enough in many applications, but an issue with the Redis process or
# a power outage may result into a few minutes of writes lost (depending on
# the configured save points).
#
# The Append Only File is an alternative persistence mode that provides
# much better durability. For instance using the default data fsync policy
# (see later in the config file) Redis can lose just one second of writes in a
# dramatic event like a server power outage, or a single write if something
# wrong with the Redis process itself happens, but the operating system is
# still running correctly.
#
# AOF and RDB persistence can be enabled at the same time without problems.
# If the AOF is enabled on startup Redis will load the AOF, that is the file
# with the better durability guarantees.
#
# Please check https://redis.io/topics/persistence for more information.

appendonly no
```
appendonly 配置是否开启AOF功能，默认 no
> AOF 会记录 Redis 接收到的每个写指令，以便重启时再次加载。当RDB和AOF持都开启时，Redis 启动时优先使用AOF加载数据，因为AOF更能保证数据不丢失，但是加载速度更慢

#### appendfilename
```bash
# The base name of the append only file.

# Redis 7 and newer use a set of append-only files to persist the dataset
# and changes applied to it. There are two basic types of files in use:

# - Base files, which are a snapshot representing the complete state of the
#   dataset at the time the file was created. Base files can be either in
#   the form of RDB (binary serialized) or AOF (textual commands).
# - Incremental files, which contain additional commands that were applied
#   to the dataset following the previous file.

# In addition, manifest files are used to track the files and the order in
# which they were created and should be applied.

# Append-only file names are created by Redis following a specific pattern.
# The file name's prefix is based on the 'appendfilename' configuration
# parameter, followed by additional information about the sequence and type.

# For example, if appendfilename is set to appendonly.aof, the following file
# names could be derived:

# - appendonly.aof.1.base.rdb as a base file.
# - appendonly.aof.1.incr.aof, appendonly.aof.2.incr.aof as incremental files.
# - appendonly.aof.manifest as a manifest file.

appendfilename "appendonly.aof"
```

- Redis 7 之前：appendfilename 配置 AOF 文件名，默认文件名为 appendonly.aof
- Redis 7 及之后：appendfilename 配置 AOF 文件前缀，默认文件前缀为 appendonly.aof
#### appenddirname
```bash
# For convenience, Redis stores all persistent append-only files in a dedicated
# directory. The name of the directory is determined by the appenddirname
# configuration parameter.

appenddirname "appendonlydir"
```
appenddirname 配置 AOF 目录，默认 appendonlydir
> 从 Redis 7 开始，Redis 使用多个AOF文件来持久化数据，并放appenddirname指定的文件夹中，并由清单文件记录，appendfilename 配置项这些文件名称的前缀，包括：
> - 基本文件：AOF 重写时的 RDB/AOF 快照，如 appendonly.aof.1.base.rdb
> - 增量文件：上次创建 AOF 基本文件以来的增量改变，如 appendonly.aof.1.incr.aof 
> - 清单文件：基本文件和增量文件的清单，如 appendonly.aof.manifest
> 
![](https://cdn.nlark.com/yuque/0/2024/png/42775905/1711166978228-5befc130-33de-4f67-9092-6e071913e526.png?x-oss-process=image%2Fformat%2Cwebp#averageHue=%232b2826&from=url&id=l6tUL&originHeight=91&originWidth=799&originalType=binary&ratio=1&rotation=0&showTitle=false&status=done&style=none&title=)

#### appendfsync
```bash
# The fsync() call tells the Operating System to actually write data on disk
# instead of waiting for more data in the output buffer. Some OS will really flush
# data on disk, some other OS will just try to do it ASAP.
#
# Redis supports three different modes:
#
# no: don't fsync, just let the OS flush the data when it wants. Faster.
# always: fsync after every write to the append only log. Slow, Safest.
# everysec: fsync only one time every second. Compromise.
#
# The default is "everysec", as that's usually the right compromise between
# speed and data safety. It's up to you to understand if you can relax this to
# "no" that will let the operating system flush the output buffer when
# it wants, for better performances (but if you can live with the idea of
# some data loss consider the default persistence mode that's snapshotting),
# or on the contrary, use "always" that's very slow but a bit safer than
# everysec.
#
# More details please check the following article:
# http://antirez.com/post/redis-persistence-demystified.html
#
# If unsure, use "everysec".

# appendfsync always
appendfsync everysec
# appendfsync no
```
appendfsync 配置 AOF 缓冲区从内存同步到磁盘的频率，即 AOF 刷盘策略，默认 everysec
> 刷盘策略有三种：
> - always: 每次有写操作时立即同步到磁盘。这种方式最安全，但性能最差
> - everysec：每秒同步一次，可能会丢失最后一秒的数据，但性能较好
> - no: 完全依赖操作系统的同步机制，性能最佳，但在系统崩溃时可能会丢失较多数据

#### no-appendfsync-on-rewrite
```bash
# When the AOF fsync policy is set to always or everysec, and a background
# saving process (a background save or AOF log background rewriting) is
# performing a lot of I/O against the disk, in some Linux configurations
# Redis may block too long on the fsync() call. Note that there is no fix for
# this currently, as even performing fsync in a different thread will block
# our synchronous write(2) call.

# In order to mitigate this problem it's possible to use the following option
# that will prevent fsync() from being called in the main process while a
# BGSAVE or BGREWRITEAOF is in progress.

# This means that while another child is saving, the durability of Redis is
# the same as "appendfsync no". In practical terms, this means that it is
# possible to lose up to 30 seconds of log in the worst scenario (with the
# default Linux settings).

# If you have latency problems turn this to "yes". Otherwise leave it as
# "no" that is the safest pick from the point of view of durability.

no-appendfsync-on-rewrite no
```
no-appendfsync-on-rewrite 配置在后台保存进程（如 BGSAVE 或 BGREWRITEAOF）进行大量 I/O 操作时，是否禁止主进程中调用 fsync()，默认no
> - yes: 在后台保存进程正在执行时，防止主进程调用 fsync()，这意味着此时 AOF 持久化相当于将 appendfsync 设置为** **no。在极端情况下，可能会丢失最多 30 秒的AOF日志
> - no: 在后台保存进程正在执行时，主进程仍然会调用 fsync()，这是为了减少因 fsync() 调用导致的潜在的长时间阻塞

#### auto-aof-rewrite-percentage
#### auto-aof-rewrite-min-size
```bash
# Automatic rewrite of the append only file.
# Redis is able to automatically rewrite the log file implicitly calling
# BGREWRITEAOF when the AOF log size grows by the specified percentage.

# This is how it works: Redis remembers the size of the AOF file after the
# latest rewrite (if no rewrite has happened since the restart, the size of
# the AOF at startup is used).

# This base size is compared to the current size. If the current size is
# bigger than the specified percentage, the rewrite is triggered. Also
# you need to specify a minimal size for the AOF file to be rewritten, this
# is useful to avoid rewriting the AOF file even if the percentage increase
# is reached but it is still pretty small.

# Specify a percentage of zero in order to disable the automatic AOF
# rewrite feature.

auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
```

- auto-aof-rewrite-percentage 配置触发 AOF 重写的百分比(相较于上次 AOF 文件大小)，默认100
- auto-aof-rewrite-min-size 配置触发 AOF 重写的最小 AOF 文件大小，默认64MB
> 当 AOF 文件大小增长到 auto-aof-rewrite-percentage 指定的百分比(相对于上次AOF文件大小)，且达到 auto-aof-rewrite-min-size  指定的最小文件大小时，会调用 BGREWRITEAOF 指令重写AOF文件

#### aof-load-truncated
```bash
# An AOF file may be found to be truncated at the end during the Redis
# startup process, when the AOF data gets loaded back into memory.
# This may happen when the system where Redis is running
# crashes, especially when an ext4 filesystem is mounted without the
# data=ordered option (however this can't happen when Redis itself
# crashes or aborts but the operating system still works correctly).

# Redis can either exit with an error when this happens, or load as much
# data as possible (the default now) and start if the AOF file is found
# to be truncated at the end. The following option controls this behavior.

# If aof-load-truncated is set to yes, a truncated AOF file is loaded and
# the Redis server starts emitting a log to inform the user of the event.
# Otherwise if the option is set to no, the server aborts with an error
# and refuses to start. When the option is set to no, the user requires
# to fix the AOF file using the "redis-check-aof" utility before to restart
# the server.

# Note that if the AOF file will be found to be corrupted in the middle
# the server will still exit with an error. This option only applies when
# Redis will try to read more data from the AOF file but not enough bytes
# will be found.
aof-load-truncated yes
```
aof-load-truncated 配置 Redis 是否加载截断的 AOF 文件时，默认yes
> Redis 由于系统崩溃或其他原因导致 AOF 文件末尾损坏或不完整
> 注意：如果AOF文件在中间会被发现损坏，Redis仍然会退出并报错。此配置仅适用于Redis尝试从AOF文件中读取更多的数据，但没有足够的字节的情况

#### aof-use-rdb-preamble
```bash
# Redis can create append-only base files in either RDB or AOF formats. Using
# the RDB format is always faster and more efficient, and disabling it is only
# supported for backward compatibility purposes.
aof-use-rdb-preamble yes
```
aof-use-rdb-preamble 配置 AOF 基础文件是否使用 RDB 格式，默认 yes
#### aof-timestamp-enabled
```bash
# Redis supports recording timestamp annotations in the AOF to support restoring
# the data from a specific point-in-time. However, using this capability changes
# the AOF format in a way that may not be compatible with existing AOF parsers.
aof-timestamp-enabled no
```
aof-timestamp-enabled 配置是否在 AOF 文件中记录时间戳，默认no
> 记录时间戳可以帮助确定写指令的时间点，以支持从特定时间点恢复数据，但可能会与现有AOF解析器不兼容

### SHUTDOWN
#### shutdown-timeout
```bash
# Maximum time to wait for replicas when shutting down, in seconds.

# During shut down, a grace period allows any lagging replicas to catch up with
# the latest replication offset before the master exists. This period can
# prevent data loss, especially for deployments without configured disk backups.

# The 'shutdown-timeout' value is the grace period's duration in seconds. It is
# only applicable when the instance has replicas. To disable the feature, set
# the value to 0.
#
# shutdown-timeout 10
```
shutdown-timeout  配置关闭 Redis 时，为滞后从节点追上最新复制偏移量所等待的最大时长，默认10秒
#### shutdown-on-sigint
#### shutdown-on-sigterm
```bash
# When Redis receives a SIGINT or SIGTERM, shutdown is initiated and by default
# an RDB snapshot is written to disk in a blocking operation if save points are configured.
# The options used on signaled shutdown can include the following values:
# default:  Saves RDB snapshot only if save points are configured.
#           Waits for lagging replicas to catch up.
# save:     Forces a DB saving operation even if no save points are configured.
# nosave:   Prevents DB saving operation even if one or more save points are configured.
# now:      Skips waiting for lagging replicas.
# force:    Ignores any errors that would normally prevent the server from exiting.
#
# Any combination of values is allowed as long as "save" and "nosave" are not set simultaneously.
# Example: "nosave force now"
#
# shutdown-on-sigint default
# shutdown-on-sigterm default
```
shutdown-on-sigint 和 shutdown-on-sigterm 配置 Redis 收到 SIGINT 或 SIGTERM 信号时的关闭行为，默认 default
> - default：根据配置的保存点（save points）决定是否保存 RDB 快照，且等待从节点同步数据
> - save： 强制执行数据库保存操作，即使没有配置保存点
> - nosave：不进行保存操作，即使配置了保存点
> - now ： 不等待滞后的从节点同步数据
> - force ： 忽略阻止服务器退出的任何错误
> 
这些选项可以组合使用，但不能同时设置 save 和 nosave

### NON-DETERMINISTIC LONG BLOCKING COMMANDS
#### lua-time-limit
#### busy-reply-threshold
```bash
# Maximum time in milliseconds for EVAL scripts, functions and in some cases
# modules' commands before Redis can start processing or rejecting other clients.

# If the maximum execution time is reached Redis will start to reply to most
# commands with a BUSY error.

# In this state Redis will only allow a handful of commands to be executed.
# For instance, SCRIPT KILL, FUNCTION KILL, SHUTDOWN NOSAVE and possibly some
# module specific 'allow-busy' commands.

# SCRIPT KILL and FUNCTION KILL will only be able to stop a script that did not
# yet call any write commands, so SHUTDOWN NOSAVE may be the only way to stop
# the server in the case a write command was already issued by the script when
# the user doesn't want to wait for the natural termination of the script.

# The default is 5 seconds. It is possible to set it to 0 or a negative value
# to disable this mechanism (uninterrupted execution). Note that in the past
# this config had a different name, which is now an alias, so both of these do
# the same:
# lua-time-limit 5000
# busy-reply-threshold 5000
```
lua-time-limit / busy-reply-threshold 配置 Redis 开始处理或拒绝其他客户端之前，EVAL 脚本、函数以及在某些情况下模块命令的最大时间，默认5秒，如果达到最大时间，Redis 将开始拒绝大部分命令，并返回 BUSY 错误
> 注意： lua-time-limit 和 busy-reply-threshold 是别名，两者效果一样

### REDIS CLUSTER
#### cluster-enabled
```bash
# Normal Redis instances can't be part of a Redis Cluster; only nodes that are
# started as cluster nodes can. In order to start a Redis instance as a
# cluster node enable the cluster support uncommenting the following:
#
# cluster-enabled yes
```
cluster-enabled 配置是否开启集群模式，默认no
#### cluster-config-file
```bash
# Every cluster node has a cluster configuration file. This file is not
# intended to be edited by hand. It is created and updated by Redis nodes.
# Every Redis Cluster node requires a different cluster configuration file.
# Make sure that instances running in the same system do not have
# overlapping cluster configuration file names.
#
# cluster-config-file nodes-6379.conf
```
cluster-config-file 配置集群的配置文件名，默认 nodes-6379.conf
> 集群运行时，集群中的每个节点都会生成一个集群配置文件，它是集群中的节点自动维护的，主要用于记录集群中有节点信息、状态以及一些参数等，以便在重启时恢复集群状态

#### cluster-node-timeout
```bash
# Cluster node timeout is the amount of milliseconds a node must be unreachable
# for it to be considered in failure state.
# Most other internal time limits are a multiple of the node timeout.
#
# cluster-node-timeout 15000
```
cluster-node-timeout 配置集群中节点的超时时间，默认15秒
> 如果在 cluster-node-timeout 时间内一直通信失败，则会被判定为主观下线，超过半数主节点认为该节点主观下线，则判断该节点客观下线，并触发故障转移流程。cluster-node-timeout 配置项跟集群内部节点通信频率和故障转移息息相关

#### cluster-port
```bash
# The cluster port is the port that the cluster bus will listen for inbound connections on. When set 
# to the default value, 0, it will be bound to the command port + 10000. Setting this value requires 
# you to specify the cluster bus port when executing cluster meet.
# cluster-port 0
```
cluster-port 配置节点的集群总线端口号，默认0，即当前节点的端口号 + 10000
> 例如，Redis 的端口号为 6379，总线端口为 16379

#### cluster-replica-validity-factor
```bash
# A replica of a failing master will avoid to start a failover if its data
# looks too old.
#
# There is no simple way for a replica to actually have an exact measure of
# its "data age", so the following two checks are performed:

# 1) If there are multiple replicas able to failover, they exchange messages
#    in order to try to give an advantage to the replica with the best
#    replication offset (more data from the master processed).
#    Replicas will try to get their rank by offset, and apply to the start
#    of the failover a delay proportional to their rank.

# 2) Every single replica computes the time of the last interaction with
#    its master. This can be the last ping or command received (if the master
#    is still in the "connected" state), or the time that elapsed since the
#    disconnection with the master (if the replication link is currently down).
#    If the last interaction is too old, the replica will not try to failover
#    at all.
#
# The point "2" can be tuned by user. Specifically a replica will not perform
# the failover if, since the last interaction with the master, the time
# elapsed is greater than:
#
#   (node-timeout * cluster-replica-validity-factor) + repl-ping-replica-period
#
# So for example if node-timeout is 30 seconds, and the cluster-replica-validity-factor
# is 10, and assuming a default repl-ping-replica-period of 10 seconds, the
# replica will not try to failover if it was not able to talk with the master
# for longer than 310 seconds.
#
# A large cluster-replica-validity-factor may allow replicas with too old data to failover
# a master, while a too small value may prevent the cluster from being able to
# elect a replica at all.
#
# For maximum availability, it is possible to set the cluster-replica-validity-factor
# to a value of 0, which means, that replicas will always try to failover the
# master regardless of the last time they interacted with the master.
# (However they'll always try to apply a delay proportional to their
# offset rank).

# Zero is the only value able to guarantee that when all the partitions heal
# the cluster will always be able to continue.
#
# cluster-replica-validity-factor 10
```
cluster-replica-validity-factor 控制 Redis 集群中从节点的有效性判断，默认10
> 当主节点宕机时，集群会检查副从节点的有效性，以确定是否可以将其提升为新的主节点。如果从节点与主节点的断开连接的时间大于 (cluster-node-timeout * replica-validity-factor) + repl-ping-replica-period，则该从节点将不会参与故障转移

#### cluster-migration-barrier
```bash
# Cluster replicas are able to migrate to orphaned masters, that are masters
# that are left without working replicas. This improves the cluster ability
# to resist to failures as otherwise an orphaned master can't be failed over
# in case of failure if it has no working replicas.

# Replicas migrate to orphaned masters only if there are still at least a
# given number of other working replicas for their old master. This number
# is the "migration barrier". A migration barrier of 1 means that a replica
# will migrate only if there is at least 1 other working replica for its master
# and so forth. It usually reflects the number of replicas you want for every
# master in your cluster.

# Default is 1 (replicas migrate only if their masters remain with at least
# one replica). To disable migration just set it to a very large value or
# set cluster-allow-replica-migration to 'no'.
# A value of 0 can be set but is useful only for debugging and dangerous
# in production.
#
# cluster-migration-barrier 1
```
cluster-migration-barrier 用于控制从节点在迁移到孤立主节点时的行为，默认1
> 当一个主节点没有从节点时，为了提高集群的容错能力，其他主节点所拥有的从节点可以迁移到这个孤立的主节点。但是，迁移只有在源主节点还有大于指定数量的从节点时才会发生。例如，默认值为1，即源主节点至少有2个从节点时才会发生迁移，参考链接：[https://blog.csdn.net/u011535541/article/details/78625330](https://blog.csdn.net/u011535541/article/details/78625330)

#### cluster-allow-replica-migration
```bash
# Turning off this option allows to use less automatic cluster configuration.
# It both disables migration to orphaned masters and migration from masters
# that became empty.
#
# Default is 'yes' (allow automatic migrations).
#
# cluster-allow-replica-migration yes
```
cluster-allow-replica-migration 是否允许从节点迁移到孤儿主节点，默认 yes
#### cluster-require-full-coverage
```bash
# By default Redis Cluster nodes stop accepting queries if they detect there
# is at least a hash slot uncovered (no available node is serving it).
# This way if the cluster is partially down (for example a range of hash slots
# are no longer covered) all the cluster becomes, eventually, unavailable.
# It automatically returns available as soon as all the slots are covered again.
#
# However sometimes you want the subset of the cluster which is working,
# to continue to accept queries for the part of the key space that is still
# covered. In order to do so, just set the cluster-require-full-coverage
# option to no.
#
# cluster-require-full-coverage yes
```
cluster-require-full-coverage 配置是否要求哈希槽全覆盖，默认 yes
> - yes：如果检测哈希槽未全覆盖，当前集群节点则会不可用
> - no：即使哈希槽未全覆盖，当前集群节点也会继续提供服务

#### cluster-replica-no-failover
```bash
# This option, when set to yes, prevents replicas from trying to failover its
# master during master failures. However the replica can still perform a
# manual failover, if forced to do so.
#
# This is useful in different scenarios, especially in the case of multiple
# data center operations, where we want one side to never be promoted if not
# in the case of a total DC failure.
#
# cluster-replica-no-failover no
```
cluster-replica-no-failover 配置是否禁止从节点在主节点宕机时自动进行故障转移，默认no
#### cluster-allow-reads-when-down
```bash
# This option, when set to yes, allows nodes to serve read traffic while the
# cluster is in a down state, as long as it believes it owns the slots.

# This is useful for two cases.  The first case is for when an application
# doesn't require consistency of data during node failures or network partitions.
# One example of this is a cache, where as long as the node has the data it
# should be able to serve it.

# The second use case is for configurations that don't meet the recommended
# three shards but want to enable cluster mode and scale later. A
# master outage in a 1 or 2 shard configuration causes a read/write outage to the
# entire cluster without this option set, with it set there is only a write outage.
# Without a quorum of masters, slot ownership will not change automatically.
#
# cluster-allow-reads-when-down no
```
cluster-allow-reads-when-down 配置当前节点集群状态为down时是否响应读请求，默认 no
#### cluster-allow-pubsubshard-when-down
```bash
# This option, when set to yes, allows nodes to serve pubsub shard traffic while
# the cluster is in a down state, as long as it believes it owns the slots.

# This is useful if the application would like to use the pubsub feature even when
# the cluster global stable state is not OK. If the application wants to make sure only
# one shard is serving a given channel, this feature should be kept as yes.
#
# cluster-allow-pubsubshard-when-down yes
```
cluster-allow-pubsubshard-when-down 配置当前节点在集群状态为 down 时是否可以继续进行 Pub/Sub 操作，默认 yes
#### cluster-link-sendbuf-limit
```bash
# Cluster link send buffer limit is the limit on the memory usage of an individual
# cluster bus link's send buffer in bytes. Cluster links would be freed if they exceed
# this limit. This is to primarily prevent send buffers from growing unbounded on links
# toward slow peers (E.g. PubSub messages being piled up).
# This limit is disabled by default. Enable this limit when 'mem_cluster_links' INFO field
# and/or 'send-buffer-allocated' entries in the 'CLUSTER LINKS` command output continuously increase.
# Minimum limit of 1gb is recommended so that cluster link buffer can fit in at least a single
# PubSub message by default. (client-query-buffer-limit default value is 1gb)
#
# cluster-link-sendbuf-limit 0
```
cluster-link-sendbuf-limit 用于限制集群节点之间发送缓冲区的大小，默认0，表示无限制
> 参考链接：[https://redis.io/commands/cluster-links/](https://redis.io/commands/cluster-links/)

#### cluster-announce-hostname
```bash
# Clusters can configure their announced hostname using this config. This is a common use case for 
# applications that need to use TLS Server Name Indication (SNI) or dealing with DNS based
# routing. By default this value is only shown as additional metadata in the CLUSTER SLOTS
# command, but can be changed using 'cluster-preferred-endpoint-type' config. This value is 
# communicated along the clusterbus to all nodes, setting it to an empty string will remove 
# the hostname and also propagate the removal.
#
# cluster-announce-hostname ""
```
cluster-announce-hostname 配置集群节点向其他节点和客户端配置的主机名，默认为空字符串
> 可以通过 CLUSTER NODES、CLUSTER SLOTS 命令查看主机名，可用于在 TLS SNI 或 DNS 路场景非

#### cluster-preferred-endpoint-type
```bash
# Clusters can advertise how clients should connect to them using either their IP address,
# a user defined hostname, or by declaring they have no endpoint. Which endpoint is
# shown as the preferred endpoint is set by using the cluster-preferred-endpoint-type
# config with values 'ip', 'hostname', or 'unknown-endpoint'. This value controls how
# the endpoint returned for MOVED/ASKING requests as well as the first field of CLUSTER SLOTS. 
# If the preferred endpoint type is set to hostname, but no announced hostname is set, a '?' 
# will be returned instead.

# When a cluster advertises itself as having an unknown endpoint, it's indicating that
# the server doesn't know how clients can reach the cluster. This can happen in certain 
# networking situations where there are multiple possible routes to the node, and the 
# server doesn't know which one the client took. In this case, the server is expecting
# the client to reach out on the same endpoint it used for making the last request, but use
# the port provided in the response.
#
# cluster-preferred-endpoint-type ip

# In order to setup your cluster make sure to read the documentation
# available at https://redis.io web site.
```
cluster-preferred-endpoint-type 配置集群返回给客户端的首选端点类型，可以是 IP 地址、主机名或未知端点，默认 ip
### CLUSTER DOCKER/NAT support
#### cluster-announce-ip
#### cluster-announce-portcluster-announce-ip
#### cluster-announce-tls-port
#### cluster-announce-bus-port
```bash
# In certain deployments, Redis Cluster nodes address discovery fails, because
# addresses are NAT-ted or because ports are forwarded (the typical case is
# Docker and other containers).
#
# In order to make Redis Cluster working in such environments, a static
# configuration where each node knows its public address is needed. The
# following four options are used for this scope, and are:
#
# * cluster-announce-ip
# * cluster-announce-port
# * cluster-announce-tls-port
# * cluster-announce-bus-port
# 
# Each instructs the node about its address, client ports (for connections
# without and with TLS) and cluster message bus port. The information is then
# published in the header of the bus packets so that other nodes will be able to
# correctly map the address of the node publishing the information.

# If cluster-tls is set to yes and cluster-announce-tls-port is omitted or set
# to zero, then cluster-announce-port refers to the TLS port. Note also that
# cluster-announce-tls-port has no effect if cluster-tls is set to no.

# If the above options are not used, the normal Redis Cluster auto-detection
# will be used instead.

# Note that when remapped, the bus port may not be at the fixed offset of
# clients port + 10000, so you can specify any port and bus-port depending
# on how they get remapped. If the bus-port is not set, a fixed offset of
# 10000 will be used as usual.
#
# Example:
#
# cluster-announce-ip 10.1.1.5
# cluster-announce-tls-port 6379
# cluster-announce-port 0
# cluster-announce-bus-port 6380
```

- cluster-announce-ip：配置节点公布的 IP 地址
- cluster-announce-port：配置节点公布的端口（无 TLS 连接）
- cluster-announce-tls-port：配置节点公布的端口（有 TLS 连接）
- cluster-announce-bus-port：配置节点公布的集群总线端口
> 在 NAT 地址转换或端口转发的情况下（如 Docker 容器），访问Redis 节点的地址可能会失败，为了使 集群正常工作，需要使用静态配置

### SLOW LOG
#### slowlog-log-slower-than
```bash
# The Redis Slow Log is a system to log queries that exceeded a specified
# execution time. The execution time does not include the I/O operations
# like talking with the client, sending the reply and so forth,
# but just the time needed to actually execute the command (this is the only
# stage of command execution where the thread is blocked and can not serve
# other requests in the meantime).
#
# You can configure the slow log with two parameters: one tells Redis
# what is the execution time, in microseconds, to exceed in order for the
# command to get logged, and the other parameter is the length of the
# slow log. When a new command is logged the oldest one is removed from the
# queue of logged commands.

# The following time is expressed in microseconds, so 1000000 is equivalent
# to one second. Note that a negative number disables the slow log, while
# a value of zero forces the logging of every command.
slowlog-log-slower-than 10000
```
slowlog-log-slower-than 配置慢日志阈值，默认10毫秒，即执行时间超过10毫秒的指令将被记录到慢日志中
#### slowlog-max-len
```bash
# There is no limit to this length. Just be aware that it will consume memory.
# You can reclaim memory used by the slow log with SLOWLOG RESET.
slowlog-max-len 128
```
slowlog-max-len 配置慢日志队列长度，默认128
### LATENCY MONITOR
#### latency-monitor-threshold
```bash
# The Redis latency monitoring subsystem samples different operations
# at runtime in order to collect data related to possible sources of
# latency of a Redis instance.

# Via the LATENCY command this information is available to the user that can
# print graphs and obtain reports.

# The system only logs operations that were performed in a time equal or
# greater than the amount of milliseconds specified via the
# latency-monitor-threshold configuration directive. When its value is set
# to zero, the latency monitor is turned off.

# By default latency monitoring is disabled since it is mostly not needed
# if you don't have latency issues, and collecting data has a performance
# impact, that while very small, can be measured under big load. Latency
# monitoring can easily be enabled at runtime using the command
# "CONFIG SET latency-monitor-threshold <milliseconds>" if needed.
latency-monitor-threshold 0
```
latency-monitor-threshold 配置延时监控阈值，系统只会记录执行时间大于或等于该阈值的操作，默认0，表示关闭延迟监控
### LATENCY TRACKING
#### latency-tracking
#### latency-tracking-info-percentiles
```bash
# The Redis extended latency monitoring tracks the per command latencies and enables
# exporting the percentile distribution via the INFO latencystats command,
# and cumulative latency distributions (histograms) via the LATENCY command.
#
# By default, the extended latency monitoring is enabled since the overhead
# of keeping track of the command latency is very small.
# latency-tracking yes

# By default the exported latency percentiles via the INFO latencystats command
# are the p50, p99, and p999.
# latency-tracking-info-percentiles 50 99 99.9
```

- latency-tracking 配置是否开启扩展延迟监控，默认 yes
- latency-tracking-info-percentiles 配置导出的延迟百分比，默认 50 99 99.9
> 启用该功能后，Redis 会跟踪每个命令的延迟，并通过 INFO latencystats 命令导出延迟百分比分布，通过 LATENCY 命令导出累计延迟分布直方图

### EVENT NOTIFICATION
#### notify-keyspace-events
```bash
# Redis can notify Pub/Sub clients about events happening in the key space.
# This feature is documented at https://redis.io/topics/notifications

# For instance if keyspace events notification is enabled, and a client
# performs a DEL operation on key "foo" stored in the Database 0, two
# messages will be published via Pub/Sub:

# PUBLISH __keyspace@0__:foo del
# PUBLISH __keyevent@0__:del foo

# It is possible to select the events that Redis will notify among a set
# of classes. Every class is identified by a single character:

#  K     Keyspace events, published with __keyspace@<db>__ prefix.
#  E     Keyevent events, published with __keyevent@<db>__ prefix.
#  g     Generic commands (non-type specific) like DEL, EXPIRE, RENAME, ...
#  $     String commands
#  l     List commands
#  s     Set commands
#  h     Hash commands
#  z     Sorted set commands
#  x     Expired events (events generated every time a key expires)
#  e     Evicted events (events generated when a key is evicted for maxmemory)
#  n     New key events (Note: not included in the 'A' class)
#  t     Stream commands
#  d     Module key type events
#  m     Key-miss events (Note: It is not included in the 'A' class)
#  A     Alias for g$lshzxetd, so that the "AKE" string means all the events
#        (Except key-miss events which are excluded from 'A' due to their
#         unique nature).

#  The "notify-keyspace-events" takes as argument a string that is composed
#  of zero or multiple characters. The empty string means that notifications
#  are disabled.

#  Example: to enable list and generic events, from the point of view of the
#           event name, use:

#  notify-keyspace-events Elg

#  Example 2: to get the stream of the expired keys subscribing to channel
#             name __keyevent@0__:expired use:

#  notify-keyspace-events Ex

#  By default all notifications are disabled because most users don't need
#  this feature and the feature has some overhead. Note that if you don't
#  specify at least one of K or E, no events will be delivered.
notify-keyspace-events ""
```
notify-keyspace-events 用于配置 Redis 服务器发送的键空间通知（Keyspace Notifications），默认空字符串
> 参考链接：[https://redis.io/docs/latest/develop/use/keyspace-notifications/](https://redis.io/docs/latest/develop/use/keyspace-notifications/)

### ADVANCED CONFIG
> 本章节需要对Redis数据结构的编码有一定了解

> 从 Redis 7.0 开始，ziplist 被 listpack 取代，例如：hash-max-ziplist-entries、list-max-ziplist-size 等配置项被 hash-max-listpack-entries、list-max-listpack-size 所取代

#### hash-max-listpack-entries
#### hash-max-listpack-value
```bash
# Hashes are encoded using a memory efficient data structure when they have a
# small number of entries, and the biggest entry does not exceed a given
# threshold. These thresholds can be configured using the following directives.
hash-max-listpack-entries 512
hash-max-listpack-value 64
```

- hash-max-listpack-entries 配置 hash 在使用 listpack 编码时，允许的最大元素数量，默认 512
- hash-max-listpack-value 配置 hash 使用 listpack 编码时，允许的最大元素长度，默认 64 字节
> 上述默认值表示当 hash 中元素不超过512个，单个元素不超过64个字节时，使用 listpack 编码，否则使用 hashtable 编码

#### list-max-listpack-size
```bash
# Lists are also encoded in a special way to save a lot of space.
# The number of entries allowed per internal list node can be specified
# as a fixed maximum size or a maximum number of elements.
# For a fixed maximum size, use -5 through -1, meaning:
# -5: max size: 64 Kb  <-- not recommended for normal workloads
# -4: max size: 32 Kb  <-- not recommended
# -3: max size: 16 Kb  <-- probably not recommended
# -2: max size: 8 Kb   <-- good
# -1: max size: 4 Kb   <-- good
# Positive numbers mean store up to _exactly_ that number of elements
# per list node.
# The highest performing option is usually -2 (8 Kb size) or -1 (4 Kb size),
# but if your use case is unique, adjust the settings as necessary.
list-max-listpack-size -2
```
list-max-listpack-size 配置 list 中每个内部 listpack 节点的最大大小或最大元素数目，默认 -2
> - -5：每个quicklist节点上的 listpack 大小不能超过64 Kb
> - -4：每个quicklist节点上的 listpack 大小不能超过32 Kb
> - -3：每个quicklist节点上的 listpack 大小不能超过16 Kb
> - -2：每个quicklist节点上的 listpack 大小不能超过8 Kb
> - -1：每个quicklist节点上的 listpack 大小不能超过4 Kb
> - 取正值表示每个内部 listpack 节点的最大元素数目
> 
通常为 -2（8 KB 大小）或 -1（4 KB 大小）表现最好

#### list-compress-depth
```bash
# Lists may also be compressed.
# Compress depth is the number of quicklist ziplist nodes from *each* side of
# the list to *exclude* from compression.  The head and tail of the list
# are always uncompressed for fast push/pop operations.  Settings are:
# 0: disable all list compression
# 1: depth 1 means "don't start compressing until after 1 node into the list,
#    going from either the head or tail"
#    So: [head]->node->node->...->node->[tail]
#    [head], [tail] will always be uncompressed; inner nodes will compress.
# 2: [head]->[next]->node->node->...->node->[prev]->[tail]
#    2 here means: don't compress head or head->next or tail->prev or tail,
#    but compress all nodes between them.
# 3: [head]->[next]->[next]->node->node->...->node->[prev]->[prev]->[tail]
# etc.
list-compress-depth 0
```
list-compress-depth 配置 list 在内部使用 ziplist 或 listpack 时，从 list 两端开始不进行压缩的节点数量，默认 0
> - 0：表示不压缩。
> - n：表示 list 两端各有 n 个节点不压缩，中间的节点压缩

#### set-max-intset-entries
```bash
# Sets have a special encoding in just one case: when a set is composed
# of just strings that happen to be integers in radix 10 in the range
# of 64 bit signed integers.
# The following configuration setting sets the limit in the size of the
# set in order to use this special memory saving encoding.
set-max-intset-entries 512
```
set-max-intset-entries 配置 set 使用 intset 编码时，允许的最大整数元素数量
> intset 是一种紧凑的编码方式，适用于只包含整数的小型集合

#### zset-max-listpack-entries
#### zset-max-listpack-value
```bash
# Similarly to hashes and lists, sorted sets are also specially encoded in
# order to save a lot of space. This encoding is only used when the length and
# elements of a sorted set are below the following limits:
zset-max-listpack-entries 128
zset-max-listpack-value 64
```

- zset-max-listpack-entries 配置 zset 在使用 listpack 编码时，允许的最大元素数量，默认 128
-  zset-max-listpack-value 配置 zset 在使用 listpack 编码时，允许的最大元素长度，默认 64 字节
#### hll-sparse-max-bytes
```bash
# HyperLogLog sparse representation bytes limit. The limit includes the
# 16 bytes header. When an HyperLogLog using the sparse representation crosses
# this limit, it is converted into the dense representation.

# A value greater than 16000 is totally useless, since at that point the
# dense representation is more memory efficient.

# The suggested value is ~ 3000 in order to have the benefits of
# the space efficient encoding without slowing down too much PFADD,
# which is O(N) with the sparse encoding. The value can be raised to
# ~ 10000 when CPU is not a concern, but space is, and the data set is
# composed of many HyperLogLogs with cardinality in the 0 - 15000 range.
hll-sparse-max-bytes 3000
```
hll-sparse-max-bytes 配置 HyperLogLog 在稀疏模式（sparse mode）下的最大字节数，默认 3000
> HyperLogLog 是一种用于估算集合基数的概率数据结构，稀疏模式是一种优化，用于存储较少数量的元素以节省内存

#### stream-node-max-bytes
#### stream-node-max-entries
```bash
# Streams macro node max size / items. The stream data structure is a radix
# tree of big nodes that encode multiple items inside. Using this configuration
# it is possible to configure how big a single node can be in bytes, and the
# maximum number of items it may contain before switching to a new node when
# appending new stream entries. If any of the following settings are set to
# zero, the limit is ignored, so for instance it is possible to set just a
# max entries limit by setting max-bytes to 0 and max-entries to the desired
# value.
stream-node-max-bytes 4096
stream-node-max-entries 100
```

- stream-node-max-bytes 配置 stream 中每个节点允许的最大字节数，默认 4096 个字节
- stream-node-max-entries 配置 stream 中每个节点允许的最大元素数量，默认 100
#### activerehashing
```bash
# Active rehashing uses 1 millisecond every 100 milliseconds of CPU time in
# order to help rehashing the main Redis hash table (the one mapping top-level
# keys to values). The hash table implementation Redis uses (see dict.c)
# performs a lazy rehashing: the more operation you run into a hash table
# that is rehashing, the more rehashing "steps" are performed, so if the
# server is idle the rehashing is never complete and some more memory is used
# by the hash table.

# The default is to use this millisecond 10 times every second in order to
# actively rehash the main dictionaries, freeing memory when possible.

# If unsure:
# use "activerehashing no" if you have hard latency requirements and it is
# not a good thing in your environment that Redis can reply from time to time
# to queries with 2 milliseconds delay.

# use "activerehashing yes" if you don't have such hard requirements but
# want to free memory asap when possible.
activerehashing yes
```
activerehashing 配置 Redis 是否启用主动 rehashing，默认 yes，即 Redis 每 100 毫秒 CPU 时间会使用 1 毫秒来 rehashing 主哈希表
#### client-output-buffer-limit 
```bash
# The client output buffer limits can be used to force disconnection of clients
# that are not reading data from the server fast enough for some reason (a
# common reason is that a Pub/Sub client can't consume messages as fast as the
# publisher can produce them).

# The limit can be set differently for the three different classes of clients:

# normal -> normal clients including MONITOR clients
# replica -> replica clients
# pubsub -> clients subscribed to at least one pubsub channel or pattern

# The syntax of every client-output-buffer-limit directive is the following:

# client-output-buffer-limit <class> <hard limit> <soft limit> <soft seconds>

# A client is immediately disconnected once the hard limit is reached, or if
# the soft limit is reached and remains reached for the specified number of
# seconds (continuously).
# So for instance if the hard limit is 32 megabytes and the soft limit is
# 16 megabytes / 10 seconds, the client will get disconnected immediately
# if the size of the output buffers reach 32 megabytes, but will also get
# disconnected if the client reaches 16 megabytes and continuously overcomes
# the limit for 10 seconds.

# By default normal clients are not limited because they don't receive data
# without asking (in a push way), but just after a request, so only
# asynchronous clients may create a scenario where data is requested faster
# than it can read.

# Instead there is a default limit for pubsub and replica clients, since
# subscribers and replicas receive data in a push fashion.

# Note that it doesn't make sense to set the replica clients output buffer
# limit lower than the repl-backlog-size config (partial sync will succeed
# and then replica will get disconnected).
# Such a configuration is ignored (the size of repl-backlog-size will be used).
# This doesn't have memory consumption implications since the replica client
# will share the backlog buffers memory.

# Both the hard or the soft limit can be disabled by setting them to zero.
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
```
client-output-buffer-limit 限制客户端的输出缓冲区大小
> - client-output-buffer-limit normal 0 0 0：限制普通客户端的输出缓冲区大小，默认 0 0 0，表示没有限制
> - client-output-buffer-limit replica 256mb 64mb 60：限制从节点客户端的输出缓冲区大小，默认 256mb 64mb 60，表示超过 256MB则断开连接，或 60 秒内持续超过 64MB，则断开连接
> - client-output-buffer-limit pubsub 32mb 8mb 60：限制发布订阅客户端的输出缓冲区大小，默认 32mb 8mb 60，表示超过 32MB则断开连接，或 60 秒内持续超过 8MB，则断开连接

#### client-query-buffer-limit
```bash
# Client query buffers accumulate new commands. They are limited to a fixed
# amount by default in order to avoid that a protocol desynchronization (for
# instance due to a bug in the client) will lead to unbound memory usage in
# the query buffer. However you can configure it here if you have very special
# needs, such us huge multi/exec requests or alike.
#
# client-query-buffer-limit 1gb
```
client-query-buffer-limit 限制客户端输入缓冲区大小，默认 1 GB
#### maxmemory-clients
```bash
# In some scenarios client connections can hog up memory leading to OOM
# errors or data eviction. To avoid this we can cap the accumulated memory
# used by all client connections (all pubsub and normal clients). Once we
# reach that limit connections will be dropped by the server freeing up
# memory. The server will attempt to drop the connections using the most 
# memory first. We call this mechanism "client eviction".
#
# Client eviction is configured using the maxmemory-clients setting as follows:
# 0 - client eviction is disabled (default)
#
# A memory value can be used for the client eviction threshold,
# for example:
# maxmemory-clients 1g
#
# A percentage value (between 1% and 100%) means the client eviction threshold
# is based on a percentage of the maxmemory setting. For example to set client
# eviction at 5% of maxmemory:
# maxmemory-clients 5%
```
maxmemory-clients 配置所有客户端连接（包括 Pub/Sub 和普通客户端）使用的最大内存量，一旦达到这个限制，Redis 会开始驱逐一些客户端连接以释放内存，默认 0，可以设置具体的值或百分比，0 表示禁用此机制
#### proto-max-bulk-len
```bash
# In the Redis protocol, bulk requests, that are, elements representing single
# strings, are normally limited to 512 mb. However you can change this limit
# here, but must be 1mb or greater
#
# proto-max-bulk-len 512mb
```
proto-max-bulk-len 配置单个字符串的最大长度，默认 512MB
#### hz
```bash
# Redis calls an internal function to perform many background tasks, like
# closing connections of clients in timeout, purging expired keys that are
# never requested, and so forth.

# Not all tasks are performed with the same frequency, but Redis checks for
# tasks to perform according to the specified "hz" value.

# By default "hz" is set to 10. Raising the value will use more CPU when
# Redis is idle, but at the same time will make Redis more responsive when
# there are many keys expiring at the same time, and timeouts may be
# handled with more precision.

# The range is between 1 and 500, however a value over 100 is usually not
# a good idea. Most users should use the default of 10 and raise this up to
# 100 only in environments where very low latency is required.
hz 10
```
hz 配置 Redis 进行内部任务（如关闭空闲连接、触发过期键的删除、执行数据持久化等）的频率，默认10，即 Redis 每秒执行 10 次
#### dynamic-hz
```bash
# Normally it is useful to have an HZ value which is proportional to the
# number of clients connected. This is useful in order, for instance, to
# avoid too many clients are processed for each background task invocation
# in order to avoid latency spikes.

# Since the default HZ value by default is conservatively set to 10, Redis
# offers, and enables by default, the ability to use an adaptive HZ value
# which will temporarily raise when there are many connected clients.

# When dynamic HZ is enabled, the actual configured HZ will be used
# as a baseline, but multiples of the configured HZ value will be actually
# used as needed once more clients are connected. In this way an idle
# instance will use very little CPU time while a busy instance will be
# more responsive.
dynamic-hz yes
```
dynamic-hz 配置是否动态调整 hz 的值，默认 yes
> 启用 dynamic-hz 后，Redis 将根据服务器的负载动态调整 hz 值。在高负载情况下，hz 值会自动增加，以更频繁地执行内部任务；在低负载情况下，hz 值会降低，从而减少不必要的 CPU 消耗

#### aof-rewrite-incremental-fsync
```bash
# When a child rewrites the AOF file, if the following option is enabled
# the file will be fsync-ed every 4 MB of data generated. This is useful
# in order to commit the file to the disk more incrementally and avoid
# big latency spikes.
aof-rewrite-incremental-fsync yes
```
aof-rewrite-incremental-fsync 配置 Redis 子进程在 AOF 重写时的行为，默认yes，即每生成 4MB 数据执行一次 fsync 操作，即将AOF文件渐进地写到磁盘，避免在重写结束时一次性刷盘造成延迟
#### rdb-save-incremental-fsync
```bash
# When redis saves RDB file, if the following option is enabled
# the file will be fsync-ed every 4 MB of data generated. This is useful
# in order to commit the file to the disk more incrementally and avoid
# big latency spikes.
rdb-save-incremental-fsync yes
```
rdb-save-incremental-fsync 配置 Redis 子进程在保存 RDB 快照时的行为，默认yes，即每生成 4MB 数据执行一次 fsync 操作，即将 RDB 快照渐进地写到磁盘，避免在重写结束时一次性刷盘造成延迟
#### lfu-log-factor
#### lfu-decay-time
```bash
# Redis LFU eviction (see maxmemory setting) can be tuned. However it is a good
# idea to start with the default settings and only change them after investigating
# how to improve the performances and how the keys LFU change over time, which
# is possible to inspect via the OBJECT FREQ command.

# There are two tunable parameters in the Redis LFU implementation: the
# counter logarithm factor and the counter decay time. It is important to
# understand what the two parameters mean before changing them.

# The LFU counter is just 8 bits per key, it's maximum value is 255, so Redis
# uses a probabilistic increment with logarithmic behavior. Given the value
# of the old counter, when a key is accessed, the counter is incremented in
# this way:

# 1. A random number R between 0 and 1 is extracted.
# 2. A probability P is calculated as 1/(old_value*lfu_log_factor+1).
# 3. The counter is incremented only if R < P.

# The default lfu-log-factor is 10. This is a table of how the frequency
# counter changes with a different number of accesses with different
# logarithmic factors:
#
# +--------+------------+------------+------------+------------+------------+
# | factor | 100 hits   | 1000 hits  | 100K hits  | 1M hits    | 10M hits   |
# +--------+------------+------------+------------+------------+------------+
# | 0      | 104        | 255        | 255        | 255        | 255        |
# +--------+------------+------------+------------+------------+------------+
# | 1      | 18         | 49         | 255        | 255        | 255        |
# +--------+------------+------------+------------+------------+------------+
# | 10     | 10         | 18         | 142        | 255        | 255        |
# +--------+------------+------------+------------+------------+------------+
# | 100    | 8          | 11         | 49         | 143        | 255        |
# +--------+------------+------------+------------+------------+------------+
#
# NOTE: The above table was obtained by running the following commands:
#
#   redis-benchmark -n 1000000 incr foo
#   redis-cli object freq foo
#
# NOTE 2: The counter initial value is 5 in order to give new objects a chance
# to accumulate hits.
#
# The counter decay time is the time, in minutes, that must elapse in order
# for the key counter to be divided by two (or decremented if it has a value
# less <= 10).
#
# The default value for the lfu-decay-time is 1. A special value of 0 means to
# decay the counter every time it happens to be scanned.
#
# lfu-log-factor 10
# lfu-decay-time 1
```

- lfu-log-factor 配置 LFU 计数器的增长速度，默认10，值越大，计数器增长越慢
- lfu-decay-time 配置 LFU 计数器的衰减速度，默认1分钟，值越大，衰减速度越慢
### ACTIVE DEFRAGMENTATION
#### activedefrag
```bash
# What is active defragmentation?
# -------------------------------
#
# Active (online) defragmentation allows a Redis server to compact the
# spaces left between small allocations and deallocations of data in memory,
# thus allowing to reclaim back memory.
#
# Fragmentation is a natural process that happens with every allocator (but
# less so with Jemalloc, fortunately) and certain workloads. Normally a server
# restart is needed in order to lower the fragmentation, or at least to flush
# away all the data and create it again. However thanks to this feature
# implemented by Oran Agra for Redis 4.0 this process can happen at runtime
# in a "hot" way, while the server is running.
#
# Basically when the fragmentation is over a certain level (see the
# configuration options below) Redis will start to create new copies of the
# values in contiguous memory regions by exploiting certain specific Jemalloc
# features (in order to understand if an allocation is causing fragmentation
# and to allocate it in a better place), and at the same time, will release the
# old copies of the data. This process, repeated incrementally for all the keys
# will cause the fragmentation to drop back to normal values.
#
# Important things to understand:
#
# 1. This feature is disabled by default, and only works if you compiled Redis
#    to use the copy of Jemalloc we ship with the source code of Redis.
#    This is the default with Linux builds.
#
# 2. You never need to enable this feature if you don't have fragmentation
#    issues.
#
# 3. Once you experience fragmentation, you can enable this feature when
#    needed with the command "CONFIG SET activedefrag yes".
#
# The configuration parameters are able to fine tune the behavior of the
# defragmentation process. If you are not sure about what they mean it is
# a good idea to leave the defaults untouched.

# Active defragmentation is disabled by default
# activedefrag no
```
activedefrag 配置是否开启主动碎片整理，默认 no
#### active-defrag-ignore-bytes
```bash
# Minimum amount of fragmentation waste to start active defrag
# active-defrag-ignore-bytes 100mb
```
active-defrag-ignore-bytes 配置碎片整理时应忽略的最小内存块大小，默认100MB
#### active-defrag-threshold-lower
```bash
# Minimum percentage of fragmentation to start active defrag
# active-defrag-threshold-lower 10
```
active-defrag-threshold-lower 配置主动碎片整理开始工作的阈值下限，默认10%，即当碎片率（fragmentation ratio）超过此值时，开始进行碎片整理
#### active-defrag-threshold-upper
```bash
# Maximum percentage of fragmentation at which we use maximum effort
# active-defrag-threshold-upper 100
```
active-defrag-threshold-upper  配置主动碎片整理的上限阈值，默认100%，即当碎片率（fragmentation ratio）超过此值时，主动碎片整理将以最大努力工作
#### active-defrag-cycle-min
```bash
# Minimal effort for defrag in CPU percentage, to be used when the lower
# threshold is reached
# active-defrag-cycle-min 1
```
active-defrag-cycle-min 配置每个碎片整理周期内，Redis使用CPU的最小比例，默认1%
#### active-defrag-cycle-max
```bash
# Maximal effort for defrag in CPU percentage, to be used when the upper
# threshold is reached
# active-defrag-cycle-max 25
```
active-defrag-cycle-max 配置每个碎片整理周期内，Redis使用CPU的最大比例，默认25%
#### active-defrag-max-scan-fields
```bash
# Maximum number of set/hash/zset/list fields that will be processed from
# the main dictionary scan
# active-defrag-max-scan-fields 1000
```
active-defrag-max-scan-fields 配置每个碎片整理周期内扫描的最大字段数，默认1000
#### jemalloc-bg-thread
```bash
# Jemalloc background thread for purging will be enabled by default
jemalloc-bg-thread yes
```
jemalloc-bg-thread 配置是否启用 jemalloc 后台线程，默认 yes，jemalloc 后台线程用于异步释放内存，从而减少主线程的内存释放负担，提高性能
#### server_cpulist
#### bio_cpulist
#### aof_rewrite_cpulist
#### bgsave_cpulist
```bash
# It is possible to pin different threads and processes of Redis to specific
# CPUs in your system, in order to maximize the performances of the server.
# This is useful both in order to pin different Redis threads in different
# CPUs, but also in order to make sure that multiple Redis instances running
# in the same host will be pinned to different CPUs.
#
# Normally you can do this using the "taskset" command, however it is also
# possible to this via Redis configuration directly, both in Linux and FreeBSD.
#
# You can pin the server/IO threads, bio threads, aof rewrite child process, and
# the bgsave child process. The syntax to specify the cpu list is the same as
# the taskset command:
#
# Set redis server/io threads to cpu affinity 0,2,4,6:
# server_cpulist 0-7:2
#
# Set bio threads to cpu affinity 1,3:
# bio_cpulist 1,3
#
# Set aof rewrite child process to cpu affinity 8,9,10,11:
# aof_rewrite_cpulist 8-11
#
# Set bgsave child process to cpu affinity 1,10,11
# bgsave_cpulist 1,10-11
```

- server_cpulist 配置将Redis服务器、IO线程固定到指定CPU，无默认值
- bio_cpulist 配置将BIO线程固定到指定CPU，无默认值
- aof_rewrite_cpulist 配置将AOF重写子进程固定到指定CPU，无默认值
- bgsave_cpulist 配置将bgsave子进程固定到指定CPU，无默认值
> 要熟悉 CPU 架构，做好充分的测试，否则可能适得其反，导致 Redis 性能下降

#### ignore-warnings
```bash
# In some cases redis will emit warnings and even refuse to start if it detects
# that the system is in bad state, it is possible to suppress these warnings
# by setting the following config which takes a space delimited list of warnings
# to suppress
#
# ignore-warnings ARM64-COW-BUG
```
 ignore-warnings 配置抑制特定的警告，无默认值
