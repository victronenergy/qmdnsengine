QT *= core
QT *= network

isEmpty(MDNSSCANNER) MDNSSCANNER = $$PWD

MDNSENGINE = $$MDNSSCANNER/..

DEFINES += DEBUG_MDNSSCANNER_MESSAGES_DEBUG=0

INCLUDEPATH *= $$MDNSSCANNER
INCLUDEPATH *= $$MDNSENGINE/src
INCLUDEPATH *= $$MDNSENGINE/src/include/qmdnsengine
INCLUDEPATH *= $$MDNSENGINE/src/src

# MDNS ENGINE
HEADERS += $$MDNSENGINE/src/qmdnsengine_export.h
HEADERS += $$MDNSENGINE/src/src/bitmap_p.h
HEADERS += $$MDNSENGINE/src/src/query_p.h
HEADERS += $$MDNSENGINE/src/src/record_p.h
HEADERS += $$MDNSENGINE/src/src/message_p.h
HEADERS += $$MDNSENGINE/src/src/server_p.h
HEADERS += $$MDNSENGINE/src/include/qmdnsengine/abstractserver.h
HEADERS += $$MDNSENGINE/src/include/qmdnsengine/bitmap.h
HEADERS += $$MDNSENGINE/src/include/qmdnsengine/dns.h
HEADERS += $$MDNSENGINE/src/include/qmdnsengine/mdns.h
HEADERS += $$MDNSENGINE/src/include/qmdnsengine/message.h
HEADERS += $$MDNSENGINE/src/include/qmdnsengine/query.h
HEADERS += $$MDNSENGINE/src/include/qmdnsengine/record.h
HEADERS += $$MDNSENGINE/src/include/qmdnsengine/server.h

SOURCES += $$MDNSENGINE/src/src/abstractserver.cpp
SOURCES += $$MDNSENGINE/src/src/bitmap.cpp
SOURCES += $$MDNSENGINE/src/src/dns.cpp
SOURCES += $$MDNSENGINE/src/src/mdns.cpp
SOURCES += $$MDNSENGINE/src/src/message.cpp
SOURCES += $$MDNSENGINE/src/src/query.cpp
SOURCES += $$MDNSENGINE/src/src/record.cpp
SOURCES += $$MDNSENGINE/src/src/server.cpp

# MDNS SCANNER
HEADERS += $$MDNSSCANNER/mdnsscanner.h
SOURCES += $$MDNSSCANNER/mdnsscanner.cpp

