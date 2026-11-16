#include "common/firmware_package.h"

#include <QFile>
#include <QtEndian>

namespace fwds {

namespace {

const char kPackageMagic[4] = {'F', 'W', 'P', 'K'};
const quint16 kPackageFormat = 1;

// 从 file 里正好读出 size 字节；读不够返回 false。
bool readExact(QIODevice* file, qint64 size, QByteArray* out) {
  *out = file->read(size);
  return out->size() == size;
}

// 把一个大端整数追加到字节串末尾。
template <class T>
void appendBigEndian(QByteArray* bytes, T value) {
  char buffer[sizeof(T)];
  qToBigEndian<T>(value, buffer);
  bytes->append(buffer, sizeof(T));
}

}  // namespace

QByteArray buildPackageHeader(const QByteArray& manifestRaw, const QByteArray& signature,
                              qint64 imageSize) {
  QByteArray header(kPackageMagic, sizeof(kPackageMagic));
  appendBigEndian<quint16>(&header, kPackageFormat);
  appendBigEndian<quint32>(&header, static_cast<quint32>(manifestRaw.size()));
  header.append(manifestRaw);
  appendBigEndian<quint16>(&header, static_cast<quint16>(signature.size()));
  header.append(signature);
  appendBigEndian<quint64>(&header, static_cast<quint64>(imageSize));
  return header;
}

bool readPackageHeader(QIODevice* file, PackageHeader* out, QString* error) {
  const qint64 fileSize = file->size();
  QByteArray field;

  // magic 4 + format 2 + manifest_len 4
  if (!readExact(file, 10, &field) || memcmp(field.constData(), kPackageMagic, 4) != 0) {
    *error = QStringLiteral("不是 .fwpkg 固件包");
    return false;
  }
  if (qFromBigEndian<quint16>(field.constData() + 4) != kPackageFormat) {
    *error = QStringLiteral("不支持的固件包格式版本");
    return false;
  }
  // manifest_len：先和上限比，再和文件里剩下的字节数比，都通过才去读
  const quint32 manifestLen = qFromBigEndian<quint32>(field.constData() + 6);
  if (manifestLen == 0 || manifestLen > static_cast<quint32>(kMaxManifestSize) ||
      static_cast<qint64>(manifestLen) > fileSize - file->pos()) {
    *error = QStringLiteral("固件包的 manifest 长度字段非法");
    return false;
  }
  PackageHeader header;
  if (!readExact(file, manifestLen, &header.manifestRaw)) {
    *error = QStringLiteral("固件包读取失败");
    return false;
  }

  // sig_len 同样先校验再读取
  if (!readExact(file, 2, &field)) {
    *error = QStringLiteral("固件包不完整");
    return false;
  }
  const quint16 sigLen = qFromBigEndian<quint16>(field.constData());
  if (sigLen == 0 || sigLen > kMaxPackageSignatureSize ||
      static_cast<qint64>(sigLen) > fileSize - file->pos()) {
    *error = QStringLiteral("固件包的签名长度字段非法");
    return false;
  }
  if (!readExact(file, sigLen, &header.signature)) {
    *error = QStringLiteral("固件包读取失败");
    return false;
  }

  // image_len 必须正好等于文件剩下的字节数：不能短，后面也不能多出东西
  if (!readExact(file, 8, &field)) {
    *error = QStringLiteral("固件包不完整");
    return false;
  }
  const quint64 imageLen = qFromBigEndian<quint64>(field.constData());
  header.imageOffset = file->pos();
  if (imageLen == 0 || imageLen > static_cast<quint64>(kMaxImageSize) ||
      static_cast<qint64>(imageLen) != fileSize - header.imageOffset) {
    *error = QStringLiteral("固件包的镜像长度字段与文件实际长度不一致");
    return false;
  }
  header.imageSize = static_cast<qint64>(imageLen);

  *out = header;
  return true;
}

PackageCheck verifyPackageFile(const QString& path, const ManifestVerifier& verifier,
                               Manifest* manifest, QString* error) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly)) {
    *error = QStringLiteral("无法读取 %1").arg(path);
    return PackageCheck::BadContainer;
  }
  PackageHeader header;
  if (!readPackageHeader(&file, &header, error)) return PackageCheck::BadContainer;

  // 先验 manifest 签名，签名不对就不再往下看镜像
  Manifest verified;
  const ManifestCheck check = verifier.verify(header.manifestRaw, header.signature, &verified, error);
  if (check == ManifestCheck::BadSignature) return PackageCheck::BadSignature;
  if (check == ManifestCheck::BadContent) return PackageCheck::BadManifest;

  // 容器头里的 image_len 不受签名保护，必须和受签名保护的 image_size 一致
  if (header.imageSize != verified.imageSize) {
    *error = QStringLiteral("固件包的镜像长度与 manifest 不符");
    return PackageCheck::ImageMismatch;
  }
  // readPackageHeader 结束时读位置正好在镜像开头
  if (!verifyImage(&file, verified, error)) return PackageCheck::ImageMismatch;

  *manifest = verified;
  return PackageCheck::Ok;
}

}  // namespace fwds
