#include "server/business/license_verifier.h"

#include <QDateTime>

#include "common/security/license.h"

namespace fwds {

QString FskLicenseVerifier::check(const QString& deviceId, const QByteArray& licenseBytes) {
  License license;
  QString error;
  if (!verifyLicense(licenseBytes, *fsk_, &license, &error)) return error;
  // 第三个参数为空：服务端不比对硬件指纹
  if (!checkLicense(license, deviceId, QString(), QDateTime::currentMSecsSinceEpoch(), &error)) {
    return error;
  }
  return QString();
}

}  // namespace fwds
