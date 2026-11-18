#!/usr/bin/env python3
"""测试代理：在客户端与服务端之间转发 TCP，按 TLS 记录（5 字节头）切分，可注入故障。
用法：tls_proxy.py LISTEN_PORT TARGET_PORT MODE [ARG]
  forward                 原样转发
  cut BYTES DOWN_S        服务端→客户端累计转发超过 BYTES 字节后断开，此后 DOWN_S 秒内拒绝新连接（断网）
  flip N                  服务端→客户端第 N 条应用数据记录（类型 23）翻转载荷中 1 比特（只对第一个连接）
  flipc N                 同上，方向为客户端→服务端
  record FILE             把第一个连接中客户端→服务端的全部字节存到 FILE，供之后整段回放
  replay N                客户端→服务端第 N 条应用数据记录转发后原样再发一次（只对第一个连接）
只记录记录类型和长度，不记录内容。
"""
import socket, sys, threading, time

listen_port, target_port, mode = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
arg = sys.argv[4:]
state = {"down_until": 0.0, "conn": 0, "s2c_bytes": 0, "cut_done": False}
lock = threading.Lock()


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def records(sock):
    buf = b""
    while True:
        while len(buf) < 5 or len(buf) < 5 + int.from_bytes(buf[3:5], "big"):
            data = sock.recv(65536)
            if not data:
                return
            buf += data
        n = 5 + int.from_bytes(buf[3:5], "big")
        yield buf[:n]
        buf = buf[n:]


def pump(src, dst, direction, conn_id, pair):
    app_count = 0
    try:
        for rec in records(src):
            if rec[0] == 23:
                app_count += 1
            if mode == "record" and direction == "c2s" and conn_id == 1:
                with open(arg[0], "ab") as f:
                    f.write(rec)
            if mode in ("flip", "flipc") and direction == ("s2c" if mode == "flip" else "c2s") and conn_id == 1 and rec[0] == 23 and app_count == int(arg[0]):
                b = bytearray(rec)
                b[5 + len(rec[5:]) // 2] ^= 0x01
                rec = bytes(b)
                log(f"conn{conn_id} {direction}: flipped 1 bit in application record #{app_count} (len {len(rec) - 5})")
            dst.sendall(rec)
            if mode == "replay" and direction == "c2s" and conn_id == 1 and rec[0] == 23 and app_count == int(arg[0]):
                dst.sendall(rec)
                log(f"conn{conn_id} {direction}: replayed application record #{app_count} (len {len(rec) - 5})")
            if mode == "cut" and direction == "s2c":
                with lock:
                    state["s2c_bytes"] += len(rec)
                    if not state["cut_done"] and state["s2c_bytes"] > int(arg[0]):
                        state["cut_done"] = True
                        state["down_until"] = time.time() + float(arg[1])
                        log(f"conn{conn_id}: cut after {state['s2c_bytes']} bytes server->client, network down {arg[1]} s")
                        raise ConnectionAbortedError
    except (OSError, ConnectionAbortedError):
        pass
    finally:
        log(f"conn{conn_id} {direction}: closed after {app_count} application records")
        for s in pair:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen_port))
    srv.listen(16)
    log(f"proxy {listen_port} -> {target_port} mode={mode} {arg}")
    while True:
        c, _ = srv.accept()
        if time.time() < state["down_until"]:
            log("connection refused: network down")
            c.close()
            continue
        state["conn"] += 1
        cid = state["conn"]
        try:
            s = socket.create_connection(("127.0.0.1", target_port))
        except OSError:
            log("target unreachable, closing client connection")
            c.close()
            continue
        log(f"conn{cid} opened")
        pair = (c, s)
        threading.Thread(target=pump, args=(c, s, "c2s", cid, pair), daemon=True).start()
        threading.Thread(target=pump, args=(s, c, "s2c", cid, pair), daemon=True).start()


main()
