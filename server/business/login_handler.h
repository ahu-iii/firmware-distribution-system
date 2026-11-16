// LoginHandler：对 LOGIN 做裁决（协议 5.1、5.2 节）。
// 已完成：JSON 格式、必填字段、时间戳窗口（2002）、设备 ID 与证书名称比对（2003）。
// 注册表与指纹（2005）、许可证（2006）、失败锁定（2007）在 DeviceRegistry 等模块
// 完成后接入，位置见 handle() 里的 TODO。
#pragma once

#include <QObject>

#include "common/config.h"
#include "server/net/session.h"

namespace fwds {

class LoginHandler : public QObject {
  Q_OBJECT
 public:
  explicit LoginHandler(const ProtocolParams& params, QObject* parent = nullptr);

 public slots:
  // 接 Session::loginRequested。
  void handle(fwds::Session* session, const QByteArray& body);

 private:
  ProtocolParams params_;
};

}  // namespace fwds
