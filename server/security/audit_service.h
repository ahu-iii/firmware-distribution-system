// AuditService：防篡改的审计日志（设计第 13 章，检查项 2-x“日志留痕”、用例 ST-23、ST-33）。
//   记录  每条日志一行：时间、级别、分类、操作者、来源主机、设备 ID、内容；
//   防改  每行的 hash = SHA-256(上一行的 hash ‖ 本行其余字段)，首行的“上一行 hash”为 64 个 0。
//         改了任何一行，这一行的 hash 就对不上；删了中间一行，下一行的 prev_hash 就对不上；
//   防删尾 删掉最后几行、或者从头整体重算哈希链，链本身看不出来，所以每 100 条和程序退出时
//         把最新的“序号 + hash”写进单独的检查点文件，并显示在界面上供审计员抄录；
//   校验  “校验日志完整性”从第一行开始重算，报告第一条对不上的记录。
// 只有追加和读取，没有修改、删除日志的接口。日志内容由调用方保证不含口令、密钥和完整报文。
#pragma once

#include <QDateTime>
#include <QList>
#include <QObject>
#include <QString>

#include "server/storage/database.h"

namespace fwds {

// 审计日志分类（设计第 13 章）。
namespace audit {
inline const QString kConn = QStringLiteral("CONN");
inline const QString kAuth = QStringLiteral("AUTH");
inline const QString kHeartbeat = QStringLiteral("HB");
inline const QString kRollout = QStringLiteral("ROLLOUT");
inline const QString kUpgrade = QStringLiteral("UPGRADE");
inline const QString kSecurity = QStringLiteral("SECURITY");
inline const QString kAdmin = QStringLiteral("ADMIN");
}  // namespace audit

struct AuditEntry {
  qint64 id = 0;
  QDateTime ts;
  QString level;     // INFO / WARN
  QString category;  // 见上面的分类
  QString actor;     // 操作者账号；系统自动动作为 system，设备上报为设备 ID
  QString source;    // 来源主机：操作员所在的主机名，或设备的 IP
  QString deviceId;  // 相关设备，没有则为空串
  QString message;
  QString prevHash;  // 上一行的 hash（十六进制）
  QString hash;      // 本行的 hash（十六进制）
};

// 完整性校验的结果。
struct AuditCheck {
  bool ok = false;
  qint64 checkedRows = 0;
  qint64 firstBadId = 0;  // 第一条对不上的记录的序号；不是某一行的问题（如检查点）时为 0
  QString detail;         // 给审计员看的说明
};

class AuditService : public QObject {
  Q_OBJECT
 public:
  AuditService(Database* db, const QString& checkpointFile, QObject* parent = nullptr);
  ~AuditService() override;

  // 启动时调用：读出最后一行的序号和 hash，后面追加的记录接在它后面。
  bool load(QString* error);

  // 追加一条日志。写库失败时只能写进程日志，返回 false。
  bool append(const QString& category, const QString& level, const QString& actor,
              const QString& source, const QString& deviceId, const QString& message);

  // 最近的 limit 条，从新到旧；category 非空时只取这一类。
  QList<AuditEntry> recent(int limit, const QString& category = QString()) const;

  // 从第一行开始重算哈希链，并核对检查点文件。
  AuditCheck verify() const;

  // 哈希链最新的 hash 和条数，界面显示给审计员抄录。
  QString lastHash() const { return lastHash_; }
  qint64 lastId() const { return lastId_; }

  // 把最新的“序号 + hash”写进检查点文件。每 100 条自动写一次，程序退出时（析构）再写一次。
  bool writeCheckpoint(QString* error);

  // 本程序所在的主机名：服务端界面上的操作都从这台主机发出，记为“来源主机”。
  static QString localSource();

 signals:
  void appended();

 private:
  // 按设计第 13 章的规则算一行的 hash。
  static QString computeHash(const AuditEntry& entry);

  Database* db_;
  QString checkpointFile_;
  qint64 lastId_ = 0;
  QString lastHash_;
};

// 哈希链第一行的 prev_hash：64 个 0。
inline const QString kAuditGenesisHash = QString(64, QLatin1Char('0'));

}  // namespace fwds
