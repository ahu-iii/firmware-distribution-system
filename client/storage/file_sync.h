// 刷盘：让操作系统把文件里已写入的数据真正写到磁盘上。
// QFile::flush() 只是把 Qt 自己的缓冲交给操作系统，数据可能还在系统缓存里，断电会丢。
// 断点续传的 .part 和固件分区的 firmware.bin 都要先刷盘，再更新“写完了”的记录。
#pragma once

#include <QFile>

#ifdef Q_OS_WIN
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace fwds {

inline bool syncToDisk(QFile* file) {
  if (!file->flush()) return false;
#ifdef Q_OS_WIN
  return _commit(file->handle()) == 0;
#elif defined(Q_OS_MACOS)
  // macOS 的 fsync 只把数据交给磁盘，不要求磁盘清空自己的写缓存；F_FULLFSYNC 才会。
  // 个别文件系统不支持 F_FULLFSYNC，这时退回 fsync
  if (fcntl(file->handle(), F_FULLFSYNC) == 0) return true;
  return fsync(file->handle()) == 0;
#else
  return fsync(file->handle()) == 0;
#endif
}

}  // namespace fwds
