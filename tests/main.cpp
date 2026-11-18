// 测试入口：网络层的测试要用 Qt 事件循环，界面测试要用 QApplication，所以自己写 main。
// 没有指定显示平台时用 offscreen：界面测试不弹窗口，在没有图形环境的机器上也能跑。
#include <QApplication>
#include <gtest/gtest.h>

int main(int argc, char** argv) {
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) qputenv("QT_QPA_PLATFORM", "offscreen");
  QApplication app(argc, argv);
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
