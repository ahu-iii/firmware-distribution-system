// 固件分区（设计 4.5、5.2 节）：用设备数据目录下的两个子目录模拟 Flash 的 A/B 两个分区。
//   <设备目录>/boot.json           启动配置
//   <设备目录>/slot_a/、slot_b/    每个分区三个文件：
//       firmware.bin    固件镜像
//       manifest.json   manifest 原始字节（原样保存，不重新序列化）
//       manifest.sig    FSK 对 manifest 的签名
// 分区里带着 manifest 和签名，Bootloader 每次启动都能独立地重新验一遍，不依赖“上次升级时验过”。
#pragma once

#include <QByteArray>
#include <QFile>
#include <QString>

namespace fwds {

// 设备目录的布局：各个文件在哪。
class SlotStore {
 public:
  explicit SlotStore(const QString& deviceDir);

  QString bootConfigPath() const;
  QString slotDir(const QString& slot) const;    // slot 是 "a" 或 "b"
  QString imagePath(const QString& slot) const;  // 该分区的 firmware.bin

  // 读出分区里的 manifest 原始字节和签名。两个文件都先看大小再读，超过上限的不读。
  // 任一个文件不存在、为空或超限时返回 false。
  bool readManifest(const QString& slot, QByteArray* manifestRaw, QByteArray* signature) const;

  // 该分区里有没有固件文件（出厂写入前用来确认分区是空的）。
  bool hasImage(const QString& slot) const;

 private:
  QString deviceDir_;
};

// 把一个新固件写进分区，分三步，对应升级状态机的 WRITING：
//   begin()     先删掉分区里旧的 manifest 和签名，再打开 firmware.bin 准备写
//   copySome()  从源文件拷一段过来；反复调用直到 atEnd()。分段是为了两段之间能回到事件循环
//   finish()    镜像刷盘，然后原子地写入 manifest 和签名
// 顺序是有讲究的：manifest 和签名最后才写。中途任何时候断电，分区里要么没有 manifest，
// 要么镜像不完整，Bootloader 验不过，就不会从这个分区启动。
// 调用方只把它用在非活动分区上；正在运行的分区从不被写。
class SlotWriter {
 public:
  // 把 sourcePath 文件里从 sourceOffset 开始的 imageSize 字节写进 slotDir。
  bool begin(const QString& slotDir, const QString& sourcePath, qint64 sourceOffset,
             qint64 imageSize, QString* error);

  // 再拷最多 maxBytes 字节。
  bool copySome(qint64 maxBytes, QString* error);

  bool atEnd() const { return written_ >= imageSize_; }
  qint64 written() const { return written_; }
  qint64 imageSize() const { return imageSize_; }

  bool finish(const QByteArray& manifestRaw, const QByteArray& signature, QString* error);

  // 放弃：关闭文件。分区里留下的半个镜像没有 manifest，不会被启动。
  void abort();

 private:
  QString slotDir_;
  QFile source_;
  QFile image_;
  qint64 imageSize_ = 0;
  qint64 written_ = 0;
};

}  // namespace fwds
