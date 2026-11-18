# 答辩演示的数据准备工具：组装方式与 fwds-server 相同，只调用 AdminService 建账号、注册设备、导入固件
add_executable(fwds-demo-seed demo_seed.cpp)
target_link_libraries(fwds-demo-seed PRIVATE fwds_server_lib)
