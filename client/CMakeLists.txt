# 客户端网络层、安全层、业务层、存储层编成库，主程序和单元测试都链接它
add_library(fwds_client_lib STATIC
  net/tcp_client.h
  net/tcp_client.cpp
  security/anti_rollback.h
  security/update_validator.h
  security/update_validator.cpp
  storage/chunk_bitmap.h
  storage/chunk_bitmap.cpp
  storage/resume_store.h
  storage/resume_store.cpp
  business/downloader.h
  business/downloader.cpp
)
target_link_libraries(fwds_client_lib PUBLIC fwds_common)

add_executable(fwds-client
  main.cpp
  ui/main_window.h
  ui/main_window.cpp
)
target_link_libraries(fwds-client PRIVATE fwds_client_lib Qt6::Widgets)
