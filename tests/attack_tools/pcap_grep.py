#!/usr/bin/env python3
"""ST-06：在抓包文件的原始字节里搜索明文——协议字段名、设备 ID、型号、固件镜像中的已知片段。
用法：pcap_grep.py 抓包.pcap 原始镜像.bin
命中数全为 0 说明抓包里读不出这些内容；拿一个明文文件（如 .fwpkg）当第一个参数可作阳性对照。
"""
import sys

pcap = open(sys.argv[1], 'rb').read()
img = open(sys.argv[2], 'rb').read()
needles = [b'device_id', b'"type"', b'pkg_id', b'UPDATE_NOTIFY', b'CHUNK', b'security_version',
           b'manifest', b'manifest_sig', b'release_id', b'from_index', b'heartbeat_interval',
           b'chunk_sha256', b'build_time', b'"code"', b'DEV-001', b'DEV-002', b'DEV-003',
           b'PLC-X200', b'PLC-Y300', b'FWDS', b'IFW1', b'BEGIN']
# 镜像里的 16 字节片段：开头（镜像头）、中间几处、结尾
for name, off in [('image@0', 0), ('image@4096', 4096), ('image@1MiB', 1 << 20),
                  ('image@5MiB', 5 << 20), ('image@end-32', len(img) - 32)]:
    needles.append((name, img[off:off + 16]))

print(f'pcap {sys.argv[1]}: {len(pcap)} bytes')
hits = 0
for n in needles:
    label, pat = (n.decode(), n) if isinstance(n, bytes) else n
    c = pcap.count(pat)
    hits += c
    print(f'{label:20s} {c}')
print('total hits', hits)
