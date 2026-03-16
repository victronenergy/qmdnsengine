cmake_minimum_required(VERSION 3.28)

if(NOT MDNSSCANNER)
    set(MDNSSCANNER "${CMAKE_CURRENT_LIST_DIR}")
endif()

if(NOT MDNSENGINE)
    set(MDNSENGINE "${CMAKE_CURRENT_LIST_DIR}/..")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Network)

add_library(mdnsscanner STATIC
  # qmdnsengine sources
  "${MDNSENGINE}/src/src/abstractserver.cpp"
  "${MDNSENGINE}/src/src/bitmap.cpp"
  "${MDNSENGINE}/src/src/dns.cpp"
  "${MDNSENGINE}/src/src/mdns.cpp"
  "${MDNSENGINE}/src/src/message.cpp"
  "${MDNSENGINE}/src/src/query.cpp"
  "${MDNSENGINE}/src/src/record.cpp"
  "${MDNSENGINE}/src/src/server.cpp"
  "${MDNSENGINE}/src/qmdnsengine_export.h"
  "${MDNSENGINE}/src/src/bitmap_p.h"
  "${MDNSENGINE}/src/src/query_p.h"
  "${MDNSENGINE}/src/src/record_p.h"
  "${MDNSENGINE}/src/src/message_p.h"
  "${MDNSENGINE}/src/src/server_p.h"
  "${MDNSENGINE}/src/include/qmdnsengine/abstractserver.h"
  "${MDNSENGINE}/src/include/qmdnsengine/bitmap.h"
  "${MDNSENGINE}/src/include/qmdnsengine/dns.h"
  "${MDNSENGINE}/src/include/qmdnsengine/mdns.h"
  "${MDNSENGINE}/src/include/qmdnsengine/message.h"
  "${MDNSENGINE}/src/include/qmdnsengine/query.h"
  "${MDNSENGINE}/src/include/qmdnsengine/record.h"
  "${MDNSENGINE}/src/include/qmdnsengine/server.h"
  # mdnsscanner
  mdnsscanner.cpp
  mdnsscanner.h
)

target_include_directories(mdnsscanner PUBLIC
  "${MDNSSCANNER}"
  "${MDNSENGINE}/src"
  "${MDNSENGINE}/src/include/qmdnsengine"
  "${MDNSENGINE}/src/src"
)

target_compile_definitions(mdnsscanner PUBLIC
  DEBUG_MDNSSCANNER_MESSAGES_DEBUG=0
)

target_link_libraries(mdnsscanner PRIVATE
  Qt6::Core
  Qt6::Network
)
