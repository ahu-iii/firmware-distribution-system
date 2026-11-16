#include "signer/passphrase_prompt.h"

#include <cstdio>
#include <cstring>

#include "common/security/key_store.h"

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace fwds {

namespace {

const int kMaxPassphraseLength = 256;

// 标准输入是不是终端。被重定向或由脚本启动时不是。
bool stdinIsTerminal() {
#ifdef _WIN32
  return _isatty(_fileno(stdin)) != 0;
#else
  return isatty(STDIN_FILENO) == 1;
#endif
}

// 打开或关闭终端回显。返回是否设置成功。
bool setEcho(bool on) {
#ifdef _WIN32
  const HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  if (!GetConsoleMode(handle, &mode)) return false;
  mode = on ? (mode | ENABLE_ECHO_INPUT) : (mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
  return SetConsoleMode(handle, mode) != 0;
#else
  struct termios settings;
  if (tcgetattr(STDIN_FILENO, &settings) != 0) return false;
  if (on) settings.c_lflag |= static_cast<tcflag_t>(ECHO);
  else settings.c_lflag &= ~static_cast<tcflag_t>(ECHO);
  return tcsetattr(STDIN_FILENO, TCSAFLUSH, &settings) == 0;
#endif
}

// 提示并读入一行，不回显。读到的内容直接放进 SecureBuffer，中间缓冲区用后清零。
bool readHidden(const QString& prompt, SecureBuffer* out) {
  std::fputs(prompt.toLocal8Bit().constData(), stderr);
  std::fflush(stderr);
  if (!setEcho(false)) return false;

  char line[kMaxPassphraseLength + 2];
  const bool ok = std::fgets(line, sizeof(line), stdin) != nullptr;
  setEcho(true);
  std::fputs("\n", stderr);

  if (ok) {
    size_t length = std::strlen(line);
    while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) --length;
    *out = SecureBuffer::fromBytes(line, static_cast<int>(length));
  }
  OPENSSL_cleanse(line, sizeof(line));
  return ok;
}

}  // namespace

bool obtainPassphrase(const char* envName, const QString& prompt, bool confirm,
                      SecureBuffer* passphrase, QString* error) {
  if (takePassphraseFromEnv(envName, passphrase)) return true;

  if (!stdinIsTerminal()) {
    *error = QStringLiteral("没有终端可以输入口令，也没有设置环境变量 %1")
                 .arg(QString::fromLatin1(envName));
    return false;
  }
  if (!readHidden(prompt, passphrase)) {
    *error = QStringLiteral("读取口令失败");
    return false;
  }
  if (confirm) {
    SecureBuffer again;
    if (!readHidden(QStringLiteral("再输入一遍："), &again)) {
      *error = QStringLiteral("读取口令失败");
      return false;
    }
    // 两遍输入不一致就作废，避免手滑设了一个自己也不知道的口令
    if (again.size() != passphrase->size() ||
        CRYPTO_memcmp(again.data(), passphrase->data(), static_cast<size_t>(again.size())) != 0) {
      *error = QStringLiteral("两次输入的口令不一致");
      return false;
    }
  }
  return true;
}

}  // namespace fwds
