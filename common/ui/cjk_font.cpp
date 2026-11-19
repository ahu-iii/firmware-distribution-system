#include "common/ui/cjk_font.h"

#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <QStringList>

namespace fwds {

bool ensureCjkFont(QString* hint) {
  // 系统里所有支持简体中文的字体（Linux 上由 fontconfig 提供）
  const QStringList cjkFamilies = QFontDatabase::families(QFontDatabase::SimplifiedChinese);
  if (cjkFamilies.isEmpty()) {
    *hint = QStringLiteral(
        "没有找到中文字体，界面文字会显示成方框。请安装中文字体后重新启动程序："
        "Ubuntu/Debian 用 sudo apt install fonts-noto-cjk（或 fonts-wqy-microhei），"
        "Fedora 用 sudo dnf install google-noto-sans-cjk-fonts");
    return false;
  }

  // 常见的中文字体按顺序优先，都没有就用找到的第一个
  static const char* const kPreferred[] = {
      "Noto Sans CJK SC", "Source Han Sans SC", "WenQuanYi Micro Hei",
      "WenQuanYi Zen Hei", "Droid Sans Fallback"};
  QString chosen = cjkFamilies.first();
  for (const char* name : kPreferred) {
    if (cjkFamilies.contains(QLatin1String(name))) {
      chosen = QLatin1String(name);
      break;
    }
  }

  // 原来的界面字体排第一，中文字体排第二：原字体里没有的字（中文）由第二个补上
  QFont font = QApplication::font();
  font.setFamilies({font.family(), chosen});
  QApplication::setFont(font);
  return true;
}

}  // namespace fwds
