// 测试入口：网络层的测试要用 Qt 事件循环，所以自己写 main 先建 QCoreApplication。
#include <QCoreApplication>
#include <gtest/gtest.h>

int main(int argc, char** argv) {
  QCoreApplication app(argc, argv);
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
