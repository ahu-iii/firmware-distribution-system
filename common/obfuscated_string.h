// 编译期字符串加密（设计第 15 节“加壳 + 字符串加密”）。
// 用法：FWDS_OBF("FWDS-LIC-1") 得到解密后的 QByteArray（UTF-8 字节，不含结尾的 0）。
//
// 原理：宏展开成一个 lambda，里面的 static constexpr 对象在编译时就把字面量逐字节异或上一串密钥，
// 程序文件里只有异或后的字节；运行到这里才异或回来。字面量本身只在编译期的常量表达式里出现，
// 编译器不会把它写进程序文件，用 strings 或反汇编工具搜不到明文。
// 每个字符串的密钥由所在行号和 __COUNTER__ 算出，各不相同。
//
// 这只是增加静态分析的难度，不是保密手段：密钥和算法就在程序里，动态调试一样能看到明文。
// 所以只用于签名用途前缀、自校验提示这类“不想让人一眼找到”的字符串，秘密（口令、私钥）一律不进程序。
#pragma once

#include <QByteArray>
#include <cstddef>

namespace fwds::obf {

// 第 i 个字节的密钥：对 (seed, i) 做几次乘法和移位混合，取最低 8 位。
// 全部是无符号运算，溢出按模 2^32 回绕，编译期和运行期算出的结果一样。
constexpr unsigned char keyByte(unsigned seed, std::size_t i) {
  unsigned x = seed * 2654435761u + static_cast<unsigned>(i) * 40503u + 0x9E3779B9u;
  x ^= x >> 13;
  x *= 0x5BD1E995u;
  x ^= x >> 15;
  return static_cast<unsigned char>(x & 0xFFu);
}

// N 是字面量的长度（含结尾的 0）。构造函数是 constexpr：在编译期完成加密。
template <std::size_t N>
class Blob {
 public:
  constexpr Blob(const char (&plain)[N], unsigned seed) : seed_(seed), data_{} {
    for (std::size_t i = 0; i < N; ++i) {
      data_[i] = static_cast<char>(static_cast<unsigned char>(plain[i]) ^ keyByte(seed, i));
    }
  }

  // 运行时解密。通过 volatile 指针读密文：否则编译器优化时会把整个解密过程在编译期算完，
  // 又把明文放回程序文件里
  QByteArray decrypt() const {
    const volatile char* cipher = data_;
    QByteArray plain(static_cast<qsizetype>(N - 1), Qt::Uninitialized);
    for (std::size_t i = 0; i + 1 < N; ++i) {
      plain[static_cast<qsizetype>(i)] =
          static_cast<char>(static_cast<unsigned char>(cipher[i]) ^ keyByte(seed_, i));
    }
    return plain;
  }

 private:
  unsigned seed_;
  char data_[N];
};

}  // namespace fwds::obf

#define FWDS_OBF(literal)                                                                       \
  ([]() -> QByteArray {                                                                         \
    static constexpr ::fwds::obf::Blob<sizeof(literal)> kBlob(literal, __LINE__ * 7919u + __COUNTER__); \
    return kBlob.decrypt();                                                                     \
  }())
