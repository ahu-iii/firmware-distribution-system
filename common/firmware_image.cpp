#include "common/firmware_image.h"

namespace fwds {

namespace {

const QByteArray kImageMagic = QByteArrayLiteral("IFW1");

// 把一个名字写成定长 16 字节的字段；不合格返回空数组。
QByteArray nameField(const QString& name) {
  if (name.isEmpty() || name.size() > kImageNameFieldSize) return QByteArray();
  // 只允许可见 ASCII 字符。要在转成字节之前检查：toLatin1() 会把汉字悄悄换成 '?'
  for (const QChar c : name) {
    if (c.unicode() <= 0x20 || c.unicode() >= 0x7F) return QByteArray();
  }
  return name.toLatin1().leftJustified(kImageNameFieldSize, '\0');
}

// 取出定长字段里第一个 0 之前的部分。
QString nameFromField(const QByteArray& field) {
  const qsizetype end = field.indexOf('\0');
  return QString::fromLatin1(end < 0 ? field : field.left(end));
}

}  // namespace

QByteArray buildImageHeader(const ImageHeader& header) {
  const QByteArray model = nameField(header.model);
  const QByteArray version = nameField(header.version);
  if (model.isEmpty() || version.isEmpty()) return QByteArray();
  QByteArray bytes = kImageMagic + model + version;
  bytes.append(header.selfTestFails ? '\x01' : '\x00');
  return bytes;
}

bool parseImageHeader(const QByteArray& bytes, ImageHeader* out) {
  if (bytes.size() < kImageHeaderSize || !bytes.startsWith(kImageMagic)) return false;
  out->model = nameFromField(bytes.mid(4, kImageNameFieldSize));
  out->version = nameFromField(bytes.mid(20, kImageNameFieldSize));
  // 只有明确写着 0 才算自检通过，其他任何值都按失败处理
  out->selfTestFails = bytes.at(36) != '\x00';
  return true;
}

}  // namespace fwds
