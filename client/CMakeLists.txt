# 客户端网络层、安全层、业务层、存储层编成库，主程序和单元测试都链接它
add_library(fwds_client_lib STATIC
  net/tcp_client.h
  net/tcp_client.cpp
  security/anti_rollback.h
  security/anti_rollback.cpp
  security/update_validator.h
  security/update_validator.cpp
  storage/file_sync.h
  storage/boot_config.h
  storage/boot_config.cpp
  storage/slot_store.h
  storage/slot_store.cpp
  storage/chunk_bitmap.h
  storage/chunk_bitmap.cpp
  storage/resume_store.h
  storage/resume_store.cpp
  business/downloader.h
  business/downloader.cpp
  business/bootloader.h
  business/bootloader.cpp
  business/updater.h
  business/updater.cpp
  business/provisioner.h
  business/provisioner.cpp
  business/event_outbox.h
  business/event_outbox.cpp
  business/event_reporter.h
  business/event_reporter.cpp
  business/demo_actions.h
  business/demo_actions.cpp
)
target_link_libraries(fwds_client_lib PUBLIC fwds_common)

add_executable(fwds-client
  main.cpp
  ui/main_window.h
  ui/main_window.cpp
  ui/demo_panel.h
  ui/demo_panel.cpp
  # 界面中文字体检查，服务端和客户端共用
  ${CMAKE_SOURCE_DIR}/common/ui/cjk_font.h
  ${CMAKE_SOURCE_DIR}/common/ui/cjk_font.cpp
)
target_link_libraries(fwds-client PRIVATE fwds_client_lib Qt6::Widgets)
