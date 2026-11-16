# CA、证书签发、固件签名逻辑编成库，主程序和单元测试都链接它；服务端和客户端不链接
add_library(fwds_signer_lib STATIC
  cert_builder.h
  cert_builder.cpp
  ca_store.h
  ca_store.cpp
  fsk_store.h
  fsk_store.cpp
  firmware_packer.h
  firmware_packer.cpp
  passphrase_prompt.h
  passphrase_prompt.cpp
)
target_link_libraries(fwds_signer_lib PUBLIC fwds_common)

add_executable(fwds-signer main.cpp)
target_link_libraries(fwds-signer PRIVATE fwds_signer_lib)
