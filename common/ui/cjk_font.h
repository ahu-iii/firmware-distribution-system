// 界面中文字体检查：服务端和设备客户端的界面文字都是中文。
// macOS、Windows 自带中文字体；Linux 上没装中文字体时，Qt 只能把中文画成方框。
#pragma once

#include <QString>

namespace fwds {

// 在创建窗口之前调用（需要已经有 QApplication）。
// 系统里有中文字体：把它排进界面字体的候选列表（原来的字体仍排第一，英文、数字的样子不变），返回 true。
// 一个中文字体都没有：界面会显示方框，返回 false，*hint 里是要装的字体包。
bool ensureCjkFont(QString* hint);

}  // namespace fwds
