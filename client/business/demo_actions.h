// 演示面板背后的两个动作（设计第 6 节“演示面板”）。只给演示用，正常运行不会调用。
//   篡改下载缓存  把 download/ 里正在下载（或断点暂停）的 .part 文件第一个字节取反，
//                 演示“续传前重验分片”“写入前整镜像再验”能发现本地缓存被改（ST-20）
//   模拟断电      不说 BYE、不跑析构、不刷任何缓冲，进程当场结束，
//                 和拔电源一样只留下已经刷到磁盘上的东西（FT-14）
// 模拟断网在网络层：TcpClient::setNetworkBlocked。
#pragma once

#include <QString>

namespace fwds {

// 篡改 dataDir/download/ 下最近修改的那个 .part 文件。没有下载缓存时返回 false。
// detail 给出改了哪个文件，或者为什么没改。
bool tamperDownloadCache(const QString& dataDir, QString* detail);

// 当场结束进程，退出码 kPowerLossExitCode。不会返回。
inline constexpr int kPowerLossExitCode = 99;
[[noreturn]] void simulatePowerLoss();

}  // namespace fwds
