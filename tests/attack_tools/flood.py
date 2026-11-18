#!/usr/bin/env python3
"""ST-28 / ST-29：连接洪泛与慢速连接。只发 TCP 连接或极慢的字节，不发任何有效报文。
用法：flood.py per_ip | total | slow    （服务端监听 127.0.0.1:9443）
  per_ip  从 127.0.0.10 一次开 100 个连接，统计 1 秒后还开着几个
  total   从 127.0.1.1 ~ 127.0.1.60 每个地址开 5 个，共 300 个
  slow    一个连接每秒送 1 字节 ClientHello，另一个什么都不发，记录各自多久被服务端关闭
多个源地址依赖 Linux 回环网段 127.0.0.0/8 全部可用。
"""
import socket, sys, time, select

def open_many(srcs, port=9443):
    socks = []
    for src in srcs:
        s = socket.socket(); s.bind((src, 0)); s.connect(('127.0.0.1', port)); socks.append(s)
    time.sleep(1.0)
    alive = 0
    for s in socks:
        r, _, _ = select.select([s], [], [], 0)
        if r:
            try:
                if s.recv(1) == b'': continue   # 服务端已关闭
            except OSError: continue
        alive += 1
    return socks, alive

mode = sys.argv[1]
if mode == 'per_ip':
    socks, alive = open_many(['127.0.0.10'] * 100)
    print(f'single IP 127.0.0.10: opened 100 TCP connections, still open after 1 s: {alive}, closed by server: {100 - alive}')
elif mode == 'total':
    srcs = [f'127.0.1.{i}' for i in range(1, 61) for _ in range(5)]
    socks, alive = open_many(srcs)
    print(f'60 IPs x 5: opened 300 TCP connections, still open after 1 s: {alive}, closed by server: {300 - alive}')
elif mode == 'slow':
    # 慢速握手：每秒 1 字节送一个 TLS ClientHello 的开头；另一个连接什么都不发
    a = socket.socket(); a.bind(('127.0.0.20', 0)); a.connect(('127.0.0.1', 9443))
    b = socket.socket(); b.bind(('127.0.0.21', 0)); b.connect(('127.0.0.1', 9443))
    t0 = time.time(); hello = bytes.fromhex('16030100c8010000c40303') + b'\x00' * 200
    closed = {}
    for i in range(30):
        for name, s in (('slow-1-byte-per-second', a), ('silent', b)):
            if name in closed: continue
            try:
                if name == 'slow-1-byte-per-second': s.send(hello[i:i + 1])
                r, _, _ = select.select([s], [], [], 0)
                if r and s.recv(1) == b'': closed[name] = time.time() - t0
            except OSError:
                closed[name] = time.time() - t0
        if len(closed) == 2: break
        time.sleep(1)
    for k, v in closed.items(): print(f'{k}: closed by server after {v:.1f} s')
