// SecureBuffer：存放口令、私钥明文、派生出的对称密钥（设计 11.3 节“内存”）。
// 和普通容器的区别只有一点：析构和重新分配之前先用 OPENSSL_cleanse 把内容清零，
// 不让敏感数据留在已经释放的内存里。禁止拷贝，避免同一份明文出现多个副本。
#pragma once

#include <openssl/crypto.h>

#include <cstring>
#include <vector>

namespace fwds {

class SecureBuffer {
 public:
  SecureBuffer() = default;
  explicit SecureBuffer(int size) : bytes_(static_cast<size_t>(size)) {}
  ~SecureBuffer() { wipe(); }

  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;

  // 移动之后源对象为空，明文仍然只有一份。
  SecureBuffer(SecureBuffer&& other) noexcept : bytes_(std::move(other.bytes_)) {}
  SecureBuffer& operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
      wipe();
      bytes_ = std::move(other.bytes_);
    }
    return *this;
  }

  // 从一段内存拷入。调用方负责清掉自己手里的那一份。
  static SecureBuffer fromBytes(const void* data, int size) {
    SecureBuffer out(size);
    if (size > 0) std::memcpy(out.data(), data, static_cast<size_t>(size));
    return out;
  }

  unsigned char* data() { return bytes_.data(); }
  const unsigned char* data() const { return bytes_.data(); }
  int size() const { return static_cast<int>(bytes_.size()); }
  bool isEmpty() const { return bytes_.empty(); }

  // 原地清零，长度不变。OPENSSL_cleanse 不会被编译器当成“无用写入”优化掉。
  void wipe() {
    if (!bytes_.empty()) OPENSSL_cleanse(bytes_.data(), bytes_.size());
  }

  // 清零旧内容后换成 size 字节的全零缓冲区。
  void reset(int size) {
    wipe();
    bytes_.assign(static_cast<size_t>(size), 0);
  }

 private:
  std::vector<unsigned char> bytes_;
};

}  // namespace fwds
