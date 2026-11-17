#include "client/storage/boot_config.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>

namespace fwds {

namespace {

// 取一个非负整数字段；缺失、不是整数或为负返回 false。
bool readCount(const QJsonObject& obj, const char* key, int* out) {
  const QJsonValue value = obj.value(QLatin1String(key));
  const int number = value.toInt(-1);
  // toInt 对 1.5 这样的小数返回默认值 -1，所以小数也被拒绝
  if (!value.isDouble() || number < 0) return false;
  *out = number;
  return true;
}

}  // namespace

bool isSlotName(const QString& name) {
  return name == QLatin1String("a") || name == QLatin1String("b");
}

QString otherSlot(const QString& slot) {
  return slot == QLatin1String("a") ? QStringLiteral("b") : QStringLiteral("a");
}

BootConfigLoad loadBootConfig(const QString& path, BootConfig* out) {
  QFile file(path);
  if (!file.exists()) return BootConfigLoad::Missing;
  if (!file.open(QIODevice::ReadOnly)) return BootConfigLoad::Corrupt;
  // boot.json 只有四个字段，不到 200 字节；只读 4 KB，再大也不是我们写的
  const QJsonDocument doc = QJsonDocument::fromJson(file.read(4096));
  if (!doc.isObject()) return BootConfigLoad::Corrupt;
  const QJsonObject obj = doc.object();

  BootConfig config;
  config.active = obj.value(QStringLiteral("active")).toString();
  config.pending = obj.value(QStringLiteral("pending")).toString();
  if (!isSlotName(config.active)) return BootConfigLoad::Corrupt;
  // pending 要么为空，要么是 active 之外的那个分区：新固件从不写进正在运行的分区
  if (!config.pending.isEmpty() && config.pending != otherSlot(config.active)) {
    return BootConfigLoad::Corrupt;
  }
  if (!readCount(obj, "boot_attempts", &config.bootAttempts) ||
      !readCount(obj, "min_security_version", &config.minSecurityVersion)) {
    return BootConfigLoad::Corrupt;
  }
  *out = config;
  return BootConfigLoad::Ok;
}

bool saveBootConfig(const QString& path, const BootConfig& config, QString* error) {
  QJsonObject obj;
  obj.insert(QStringLiteral("active"), config.active);
  obj.insert(QStringLiteral("pending"), config.pending);
  obj.insert(QStringLiteral("boot_attempts"), config.bootAttempts);
  obj.insert(QStringLiteral("min_security_version"), config.minSecurityVersion);

  // QSaveFile：先写临时文件并刷盘，commit() 时改名覆盖旧文件
  QSaveFile file(path);
  if (!file.open(QIODevice::WriteOnly) ||
      file.write(QJsonDocument(obj).toJson(QJsonDocument::Indented)) < 0 || !file.commit()) {
    *error = QStringLiteral("无法保存 %1：%2").arg(path, file.errorString());
    return false;
  }
  return true;
}

}  // namespace fwds
