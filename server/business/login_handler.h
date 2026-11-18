// LoginHandler：对 LOGIN 做裁决（协议 5.1、5.2 节）。按协议规定的顺序检查：
//   1. JSON 格式和必填字段（1005）
//   2. 时间戳窗口（2002）
//   3. 设备 ID 与证书名称一致（2003）
//   4. 注册表：已注册、未停用、证书指纹一致（2005）
//   5. 许可证（2006）——通过 LicenseVerifier 接口接入
//   6. 失败锁定（2007）
// 全部通过后，按 LOGIN 里的 event_base 做一次事件对账（EventStore），把 event_ack 写进 LOGIN_RESULT。
// 第 3 ~ 5 项失败会计入 LoginThrottle，同一设备或同一 IP 失败次数超限后锁定一段时间。
#pragma once

#include <QObject>

#include "common/config.h"
#include "server/business/device_registry.h"
#include "server/business/event_store.h"
#include "server/business/license_verifier.h"
#include "server/business/login_throttle.h"
#include "server/net/session.h"

namespace fwds {

class LoginHandler : public QObject {
  Q_OBJECT
 public:
  // registry、throttle 由调用方持有，必须比 LoginHandler 活得久。
  // license 可以为空指针：许可证验签模块完成之前不检查许可证。
  LoginHandler(const ProtocolParams& params, DeviceRegistry* registry, LoginThrottle* throttle,
               LicenseVerifier* license = nullptr, QObject* parent = nullptr);

 public slots:
  // 事件入库模块。不设置时 event_ack 直接取注册表里的值（部分单元测试这样用）。
  void setEventStore(EventStore* events) { events_ = events; }

  // 接 Session::loginRequested。
  void handle(fwds::Session* session, const QByteArray& body);

 private:
  // 拒绝登录并计一次失败。certName 是证书里的设备 ID（已经过 TLS 认证，不是设备自报的）。
  void rejectAndCount(Session* session, ErrorCode code, const QString& certName, qint64 nowMs);

  ProtocolParams params_;
  DeviceRegistry* registry_;
  LoginThrottle* throttle_;
  LicenseVerifier* license_;
  EventStore* events_ = nullptr;
};

}  // namespace fwds
