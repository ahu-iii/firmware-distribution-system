# 服务端的网络层和业务层编成一个库，主程序和单元测试都链接它
add_library(fwds_server_lib STATIC
  net/conn_limiter.h
  net/conn_limiter.cpp
  net/session.h
  net/session.cpp
  net/tcp_server.h
  net/tcp_server.cpp
  business/login_handler.h
  business/login_handler.cpp
)
target_link_libraries(fwds_server_lib PUBLIC fwds_common)

add_executable(fwds-server
  main.cpp
  ui/main_window.h
  ui/main_window.cpp
)
target_link_libraries(fwds-server PRIVATE fwds_server_lib Qt6::Widgets)
if(FWDS_DEV_PLAINTEXT)
  target_compile_definitions(fwds-server PRIVATE FWDS_DEV_PLAINTEXT)
endif()
