add_library(fwds_common STATIC
  protocol.h
  protocol.cpp
  frame_codec.h
  frame_codec.cpp
  config.h
  config.cpp
  log.h
  log.cpp
  net/backoff.h
  net/channel_security.h
  net/plaintext_dev_channel.h
  net/frame_channel.h
  net/frame_channel.cpp
)
target_include_directories(fwds_common PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(fwds_common PUBLIC Qt6::Core Qt6::Network)
