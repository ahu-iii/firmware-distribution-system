// 模拟固件镜像的头部（设计 5.2 节）。真实设备的镜像是机器码，这里用一个 37 字节的头代替：
//   偏移  长度  内容
//   0     4     魔数 "IFW1"
//   4     16    型号，ASCII，不足 16 字节用 0 补齐
//   20    16    版本号，ASCII，不足 16 字节用 0 补齐
//   36    1     自检标志：0 = 启动自检通过，1 = 启动自检必定失败（演示回滚用）
//   37    …     载荷（随机数据）
// 签发工具的 make-image 按这个格式生成镜像，设备端 Bootloader 的“启动自检”读这个头。
// 镜像本身受 manifest 里的哈希和签名保护，这个头不承担任何安全功能，只是让“自检”有东西可查。
#pragma once

#include <QByteArray>
#include <QString>

namespace fwds {

inline constexpr int kImageHeaderSize = 37;
inline constexpr int kImageNameFieldSize = 16;  // 型号、版本号两个字段各占的字节数

struct ImageHeader {
  QString model;
  QString version;
  bool selfTestFails = false;
};

// 生成 37 字节的头。型号或版本号为空、含非 ASCII 字符或超过 16 字节时返回空数组。
QByteArray buildImageHeader(const ImageHeader& header);

// 解析镜像开头的 37 字节。长度不够或魔数不对返回 false。
bool parseImageHeader(const QByteArray& bytes, ImageHeader* out);

}  // namespace fwds
